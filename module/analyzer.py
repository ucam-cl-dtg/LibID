# @CreateTime: May 9, 2017 10:19 AM
# @Author: Stan Zhang
# @Contact: jz448@cl.cam.ac.uk
# @Last Modified By: Stan Zhang
# @Last Modified Time: Nov 7, 2018 2:14 PM
# @Description: The Analyzer of LibID

import hashlib
import json
import os
import re
import time
from collections import Counter, OrderedDict

import networkx as nx
from datasketch import MinHash
from tqdm import tqdm

import module.config as config
from androguard.core.analysis import analysis
from androguard.core.bytecodes import apk, dvm
from androguard.util import read
from module.call_graph_matching import Method, match
from module.config import FILE_LOGGER, LOGGER, MODE


class LibAnalyzer(object):
    def __init__(self, file_path):

        self.a = None
        self.d = []
        self.dx = []

        self.classes_names = []
        self._class_dex = dict()

        self._classes_signatures = dict()
        self._classes_xref_tos = dict()
        self._classes_interfaces = dict()
        self._classes_superclass = dict()

        self.LIB_RELATIONSHIP_GRAPHS = dict()

        LOGGER.info("Start loading %s ...", os.path.basename(file_path))
        self._load_file(file_path)
        LOGGER.info("%s loaded", os.path.basename(file_path))

        # packages = [1st_level_package, ..., last_level_dir]
        # package_contents[package] = [package_contents]
        # Example:
        # packages = [("Landroid"), ..., ("Landroid/support/v4/app/demo")]
        # package_contents["Landroid/support"] = ["Landroid/support/v4",
        # "Landroid/support/v6"]
        self._package_classes = dict()
        self._signature_weight = dict()

        self._call_graph = None
        self._interface_graph = None
        self._superclass_graph = None

        # Classes that been called but not exist in the package
        self._ghost_graph = nx.MultiDiGraph()

        # Library identification related variables
        self._libs_matches = dict()
        self._package_libs_matches = dict()
        self._class_libs_matches = dict()
        self._lib_packages_matches = dict()
        self._lib_info = dict()
        self._lib_shrink_percentage = dict()
        self._lsh_classes = set()

        self._pmatch_app_classes = dict()
        self._pmatch_lib_classes = dict()
        self._pmatch_lib_app_classes = dict()

        self.mode = None
        self.consider_classes_repackaging = True
        self.shrink_threshold = None
        self.probability_threshold = None

    # Initialization related methods
    # ---------------------------------------------------------

    def _load_file(self, file_path):
        self.file_path = file_path
        file_type = os.path.splitext(file_path)[1]

        if file_type == ".apk":
            self.a = apk.APK(file_path)

            self.filename = os.path.basename(self.a.get_filename())
            self.appID = self.a.get_package()
            self.permissions = self.a.get_permissions()

            # Multidex app support
            for dex in self.a.get_dex():
                _d = dvm.DalvikVMFormat(dex)
                _dx = analysis.uVMAnalysis(_d)

                self.d.append(_d)
                self.dx.append(_dx)

            self.classes_names = self._get_classes_names()

        elif file_type == ".dex":
            _d = dvm.DalvikVMFormat(read(file_path))
            _dx = analysis.uVMAnalysis(_d)

            self.d = [_d]
            self.dx = [_dx]
            self.classes_names = self._get_classes_names()

        elif file_type == ".json":
            with open(file_path) as fd:
                data = json.load(fd)

            # If this is an app profile
            if "appID" in data:
                self.filename = data["filename"]
                self.appID = data["appID"]
                self.permissions = data["permissions"]
            # If this is a lib profile
            else:
                self.lib_name = data["name"]
                self.lib_version = data["version"]
                self.category = data["category"]
                self.root_package = data["root_package"]

            self._classes_signatures = data["classes_signatures"]
            self.classes_names = self._classes_signatures.keys()
            self._classes_xref_tos = data["classes_xref_tos"]
            self._classes_interfaces = data["classes_interfaces"]
            self._classes_superclass = data["classes_superclass"]

    def _get_classes_names(self):
        classes_names = []

        for idx, dex in enumerate(self.d):
            names = dex.get_classes_names()
            classes_names.extend(names)

            for class_name in names:
                self._class_dex[class_name] = idx

        return classes_names

    # Profiling related methods
    # ---------------------------------------------------------

    def get_classes_signatures(self):
        if not self._classes_signatures:
            for _class in self.get_classes():
                signature, xref_tos = self.get_class_signature(_class)
                self._classes_signatures[_class.name] = list(signature)
                if xref_tos:
                    self._classes_xref_tos[_class.name] = xref_tos

        return self._classes_signatures

    def get_class_signature(self, encoded_class):
        """Get the signature of an encoded class
        
        Args:
            encoded_class (dvm.ClassDefItem): The encoded class parsed by Androidguard.
        
        Returns:
            list: The list of class signatures.
        """
        signature = set()
        _xrefs = []

        descriptor = self.get_class_descriptor(encoded_class)

        dex_idx = self._class_dex[encoded_class.name]

        for method in encoded_class.get_methods():
            _sig, _xref = self.get_method_signature(
                method, descriptor, dex_idx)
            signature.update(_sig)
            _xrefs.extend(_xref)

        xrefs = dict(Counter(_xrefs))

        return signature, xrefs

    def get_class_descriptor(self, encoded_class):
        interfaces = []
        for interface in encoded_class.get_interfaces():
            if interface in config.ANDROID_SDK_CLASSES:
                interfaces.append(interface)
            else:
                if encoded_class.name in self._classes_interfaces:
                    self._classes_interfaces[encoded_class.name].append(
                        interface)
                else:
                    self._classes_interfaces[encoded_class.name] = [interface]

        interfaces.sort()

        superclass = encoded_class.get_superclassname()
        if superclass not in config.ANDROID_SDK_CLASSES:
            self._classes_superclass[encoded_class.name] = superclass
            superclass = 'X'

        descriptor = "{}[{}][{}]".format(
            encoded_class.get_access_flags_string(), superclass, "|".join(interfaces))

        return descriptor

    def get_method_signature(self, encoded_method, class_descriptor, dex_idx):
        """Get signature of an encoded method
        
        Args:
            encoded_method (dvm.EncodedMethod): The encoded method parsed by Androidguard.
            class_descriptor (str): The class descriptor.
            dex_idx (int): The index of the dex file. Some apps contain multiple dex files.
        
        Returns:
            list: The list of method signatures.
        """
        signature = set()

        descriptor = self.get_formatted_method_descriptor(
            encoded_method, class_descriptor)

        _dx = self.dx[dex_idx]
        raw_sign, xrefs = _dx.get_method_signature(
            encoded_method, predef_sign=analysis.SIGNATURE_L0_7, sdk_classes=config.ANDROID_SDK_CLASSES)
        xrefs = [self.get_formatted_xref(xref) for xref in xrefs
                 if xref.split("->")[1] not in config.ANDROID_SDK_CLASSES]

        for block in raw_sign.get_string().split("B["):
            if len(block) > 4:
                _sig = descriptor + "B[" + block
                _sig_sha1 = hashlib.sha1(_sig.encode('utf-8'))

                signature.add(_sig_sha1.hexdigest())

        return signature, xrefs

    def get_formatted_xref(self, xref):
        src_descriptor, dst_class_name, dest_descriptor = xref.split("->")

        return "{}->{}->{}".format(self.get_formatted_method_descriptor("", "", src_descriptor),
                                   dst_class_name,
                                   self.get_formatted_method_descriptor("", "", dest_descriptor))

    def get_formatted_method_descriptor(self, encoded_method, class_descriptor, method_descriptor=None):
        """Replace all obfuscatable names with X
        
        Args:
            encoded_method (dvm.EncodedMethod): The encoded method parsed by Androidguard.
            class_descriptor (str): The class descriptor.
            method_descriptor (str, optional): Defaults to None. The method descriptor.
        
        Returns:
            str: Formatted method descriptor.
        """
        descriptor = method_descriptor if method_descriptor else encoded_method.get_descriptor()
        LOGGER.debug("descriptor: %s", descriptor)
        splits = re.split(r"\(|\)", descriptor)
        input_types = splits[1].split(' ')
        return_types = splits[2].split(' ')
        types = filter(None, set(input_types).union(return_types))

        for _type in types:
            if _type[-1] == ";" and _type not in config.ANDROID_SDK_CLASSES:
                descriptor = descriptor.replace(_type, "X")

        return "%s%s" % (class_descriptor, descriptor)

    def get_relationship_graphs(self, repackage=False):
        """Get the call_graph, interface_graph and superclass_graph
            repackage (bool, optional): Defaults to False. Should LibID consider classes repackaging?
        
        Returns:
            list: invocation, interface, and inheritance graph
        """
        self.consider_classes_repackaging = repackage

        if not self._call_graph:
            self._build_call_graph()
            self._build_interface_graph()
            self._build_superclass_graph()

        return (self._call_graph, self._interface_graph, self._superclass_graph, self._ghost_graph)


    # Library identification related private methods
    # ---------------------------------------------------------

    def _build_packages_info(self):
        """Initialize self._package_classes"""
        classes_names = self.classes_names
        for class_name in classes_names:
            package_level = class_name.count("/")

            for idx in range(package_level + 1):
                package_name = self._get_package_with_level(
                    idx, class_name)
                self._add_class_to_package(class_name, package_name)

    def _has_ghost_relation(self, ghost_class):
        if ghost_class in self.classes_names:
            return False

        if self.consider_classes_repackaging:
            if ghost_class not in config.ANDROID_SDK_CLASSES:
                return True
        elif any((os.path.dirname(ghost_class) + "/").startswith(os.path.dirname(c) + "/") for c in self.classes_names):
            return True

        return False

    def _build_ghost_graph(self, src_class, ghost_class, graph_type, ghost_method=[]):
        """Initialize self._ghost_relation for the app

        The format of edge in the superclass graph is (caller_class_name, callee_name)
        Each edge has a `method` property, whose format is (src_method_descriptor, dst_method_descriptor, call_num)
        """
        if self._has_ghost_relation(ghost_class):
            if self._ghost_graph.has_edge(src_class, ghost_class):
                edge_dict = dict(self._ghost_graph[src_class][ghost_class])
                method = ghost_method
                for key in edge_dict:
                    if edge_dict[key]["type"] == graph_type:
                        if graph_type:
                            return

                        method = edge_dict[key]["method"]
                        method.extend(ghost_method)
                        self._ghost_graph.remove_edge(
                            src_class, ghost_class, key=key)

                self._ghost_graph.add_edge(
                    src_class, ghost_class, type=graph_type, method=method)
            else:
                self._ghost_graph.add_edge(
                    src_class, ghost_class, type=graph_type, method=ghost_method)

    def _build_call_graph(self):
        """Initialize self._call_graph for the app

        The format of edge in the superclass graph is (caller_class_name, callee_name)
        Each edge has a `method` property, whose format is (src_method_descriptor, dst_method_descriptor, call_num)
        """
        self._call_graph = nx.DiGraph()
        for class_name in self._classes_xref_tos:
            for xref_to in self._classes_xref_tos[class_name]:
                src_method, dst_class, dst_method = xref_to.split("->")
                # for some strange reason, dst_class could start with [ sometime
                if dst_class.startswith("["):
                    dst_class = dst_class[1:]
                self._build_ghost_graph(class_name, dst_class, 0, [
                                        (src_method, dst_method)])

                call_num = self._classes_xref_tos[class_name][xref_to]
                method_list = self._call_graph[class_name][dst_class]["method"] if self._call_graph.has_edge(
                    class_name, dst_class) else []
                method_list.append((src_method, dst_method, call_num))
                self._call_graph.add_edge(
                    class_name, dst_class, method=method_list)

    def _build_interface_graph(self):
        """Initialize self._interface_graph for the app

        The format of edge in the superclass graph is (class_name, interface_name)
        """
        self._interface_graph = nx.DiGraph()
        for class_name in self._classes_interfaces:
            for interface in self._classes_interfaces[class_name]:
                self._build_ghost_graph(class_name, interface, 1)
                self._interface_graph.add_edge(class_name, interface)

    def _build_superclass_graph(self):
        """Initialize self._superclass_graph for the app

        The format of edge in the superclass graph is (class_name, superclass_name)
        """
        self._superclass_graph = nx.DiGraph()
        for class_name in self._classes_superclass:
            self._build_ghost_graph(
                class_name, self._classes_superclass[class_name], 2)
            self._superclass_graph.add_edge(
                class_name, self._classes_superclass[class_name])

    def _add_class_to_package(self, class_name, package):
        if package in self._package_classes.keys():
            self._package_classes[package].add(class_name)
        else:
            self._package_classes[package] = set([class_name])

    def _get_package_with_level(self, level, string):
        # if it is a class match
        if string.count("->"):
            string = string.split("->")[1]

        if not level:
            return "/"

        if string.count("/") < level:
            return None

        return "/".join(string.split("/")[:level])

    def _update_dict_value_with_key(self, d, k, v):
        if k in d:
            d[k].add(v)
        else:
            d[k] = set([v])

    def _get_interfaces_num(self, class_name, lib_name=None):
        interface_graph = self.LIB_RELATIONSHIP_GRAPHS[lib_name][1] if lib_name else self._interface_graph

        if class_name in interface_graph:
            return len(interface_graph.neighbors(class_name))

        return 0

    def _get_raw_class_matches(self, class_name, lsh):
        if not self._classes_signatures:
            self.get_classes_signatures()

        class_signatures = self._classes_signatures[class_name]

        if class_signatures:
            self._lsh_classes.update([class_name])

            m = MinHash(num_perm=config.LSH_PERM_NUM)
            for signature in class_signatures:
                m.update(signature.encode('utf8'))

            matches = lsh.query(m, len(class_signatures))

            return set(matches)
        else:
            return set()

    def _get_raw_classes_matches(self, lsh, exclude_builtin):
        start_time = time.time()
        LOGGER.info("Start matching classes ...")

        for class_name in tqdm(self.classes_names):
            # Exclude builtin libraries can speed up the matching
            if exclude_builtin and class_name.startswith(("Landroid/support", "Lcom/google/android/gms")):
                self._class_libs_matches[class_name] = set()
            else:
                matches = self._get_raw_class_matches(class_name, lsh)
                self._class_libs_matches[class_name] = matches

        end_time = time.time()

        LOGGER.info("Classes matching finished. Duration: %fs", end_time - start_time)

    def _get_shrink_percentage(self, classes_names, lib_signature_num):
        signature_set = set()
        for class_name in classes_names:
            signature_set.update(self._classes_signatures[class_name])

        shrink_percentage = min(len(signature_set) /
                                float(lib_signature_num), 1)
        return shrink_percentage

    def _is_pmatch_reach_threshold(self, lib):
        lib_signature_num = int(lib.split("|")[3])

        LOGGER.debug("shrink percentage (before matching): %s, %f", lib, self._get_shrink_percentage(
            self._pmatch_app_classes[lib], lib_signature_num))

        if self._get_shrink_percentage(self._pmatch_app_classes[lib], lib_signature_num) < self.shrink_threshold:
            return False

        return True

    def _get_possible_matches(self):
        """Get all possible libraries in this app.

        If there are at least SHRINK_THRESHOLD (e.g. 15%) of matches between library and app classes,
        we regard it as a library candidate.
        """

        for class_name in self.classes_names:
            class_matches = self._class_libs_matches[class_name]

            if class_matches:
                for lib_class_match in class_matches:
                    [match_lib, match_class] = lib_class_match.split("->")
                    lib_name = match_lib.split("|")[0]

                    if self.mode == MODE.SCALABLE or self._get_interfaces_num(class_name) <= self._get_interfaces_num(match_class, lib_name):
                        self._update_dict_value_with_key(
                            self._pmatch_app_classes, match_lib, class_name)
                        self._update_dict_value_with_key(
                            self._pmatch_lib_classes, match_lib, match_class)
                        self._update_dict_value_with_key(
                            self._pmatch_lib_app_classes, match_lib, (match_class, class_name))

        for lib in self._pmatch_lib_classes.keys():
            if not self._is_pmatch_reach_threshold(lib):
                del self._pmatch_app_classes[lib], self._pmatch_lib_classes[lib], self._pmatch_lib_app_classes[lib]

    def _get_package_classes_within_call_graph(self, matched_classes_pairs, lib_name):
        # package could be '' if the root package is /
        package_classes = set()
        matched_app_classes = set(pair[1] for pair in matched_classes_pairs)

        for class_name in matched_app_classes:
            package_name = os.path.dirname(class_name)
            if package_name:
                package_classes.update(self._package_classes[package_name])
            else:
                package_classes.update(class_name)

        if self.mode == MODE.ACCURATE:
            graphs = [self._call_graph.subgraph(package_classes), self._interface_graph.subgraph(
                package_classes), self._superclass_graph.subgraph(package_classes)]
            USG = nx.compose_all(graphs).to_undirected()

            LOGGER.debug("Before removing ghost: %d", len(USG.nodes()))

            lib_ghost_graph = self.LIB_RELATIONSHIP_GRAPHS[lib_name][3]
            for pair in matched_classes_pairs:
                (lib_class, app_class) = pair

                if lib_class in lib_ghost_graph:
                    ghost_relations = lib_ghost_graph.out_edges(
                        lib_class, data=True)

                    for _, ghost_lib_class, info in ghost_relations:
                        relation_type = info["type"]
                        if app_class in graphs[relation_type]:
                            ghost_app_classes = set(graphs[relation_type].neighbors(
                                app_class)) - matched_app_classes

                            if not self.consider_classes_repackaging:
                                ghost_app_classes = set(c for c in ghost_app_classes if c.count(
                                    "/") - app_class.count("/") == ghost_lib_class.count("/") - lib_class.count("/"))
                            
                            if info["type"] == 0:
                                # Call graph
                                for ghost_app_class in ghost_app_classes:
                                    app_call_descriptors = set(
                                        m[:2] for m in graphs[0][app_class][ghost_app_class]["method"])
                                    lib_call_descriptors = set(info["method"])

                                    if ghost_app_class in USG and app_call_descriptors <= lib_call_descriptors:
                                        LOGGER.debug("Ghost app class found: [%d] %s, %s, %s, %s", 0, lib_class, app_class, ghost_lib_class, ghost_app_class)
                                        USG.remove_node(ghost_app_class)
                            else:
                                # Inheritance/Interface graph
                                LOGGER.debug("Ghost app classes found: [%d] %s, %s, %s, %s", info["type"], lib_class, app_class, ghost_lib_class, ghost_app_classes)
                                USG.remove_nodes_from(ghost_app_classes)

            LOGGER.debug("After removing ghost: %d", len(USG.nodes()))
            
            ingraph_classes = set()
            for ssg in nx.connected_component_subgraphs(USG):
                nodes = ssg.nodes()
                matched_nodes = set(nodes).intersection(matched_app_classes)

                # If classes repackaging is considered, it is very possible to mismatch other classes inside the package
                # We set a threshold in this case to remove the influence
                # threshold = 0.05 if self.consider_classes_repackaging else 0

                threshold = 0

                if len(matched_nodes) > len(nodes) * threshold:
                    ingraph_classes.update(nodes)
                else:
                    matched_app_classes -= matched_nodes

            # Some matched_app_classes may not exist in call graph
            ingraph_classes.update(matched_app_classes)

            LOGGER.debug("matched_app_classes (after): %d", len(matched_app_classes))

            return matched_app_classes, ingraph_classes
        else:
            return matched_app_classes, package_classes

    def _get_lib_match_probability(self, matched_classes_pairs, lib_name, lib_class_num, lib_signature_num):

        LOGGER.debug("matched_app_classes: %d",
                          len(matched_classes_pairs))

        LOGGER.debug(matched_classes_pairs)
        
        matched_app_classes, package_classes = self._get_package_classes_within_call_graph(
            matched_classes_pairs, lib_name)

        shrink_percentage = self._get_shrink_percentage(
            matched_app_classes, lib_signature_num)
        
        LOGGER.debug("shrink percentage (after): %f", shrink_percentage)

        if shrink_percentage < self.shrink_threshold:
            return 0

        package_classes = [
            c for c in package_classes if self._classes_signatures[c]]

        divide_classes_num = min(len(package_classes), lib_class_num)

        probability = len(matched_app_classes) / \
            float(divide_classes_num) if divide_classes_num else 0
        self._lib_shrink_percentage[lib_name] = self._get_shrink_percentage(
            package_classes, lib_signature_num)

        LOGGER.debug("matching info: %s -> %s: %d, %d, %d, %f", self.filename, lib_name, len(matched_app_classes), lib_class_num, len(package_classes), probability)
        FILE_LOGGER.debug("%s -> %s: %d, %d, %d, %f", self.filename, lib_name, len(
            matched_app_classes), lib_class_num, len(package_classes), probability)

        return probability

    def _check_package_has_subpackage(self, package):
        if package and any(cn.count("/") - package.count("/") > 1 for cn in self._package_classes[package]):
            return True

        return False

    def _bind_lib_to_package(self, lib_name, probability, package):
        self._libs_matches[lib_name] = probability

        if lib_name in self._lib_packages_matches:
            self._lib_packages_matches[lib_name].add(package)
        else:
            self._lib_packages_matches[lib_name] = set([package])

        if package in self._package_libs_matches:
            self._package_libs_matches[package].append(lib_name)
        else:
            self._package_libs_matches[package] = [lib_name]

    def _check_package_lib_match(self, lib_name, package, matched_classes_pairs, lib_class_num, lib_signature_num):
        probability = self._get_lib_match_probability(
            matched_classes_pairs, lib_name, lib_class_num, lib_signature_num)

        LOGGER.debug("probability: %s : %f", lib_name, probability)

        if probability > self.probability_threshold:
            lib_name_base = lib_name.split("_")[0] + "_"

            # If there are libraries already matched to the package
            if package in self._package_libs_matches:
                existed_lib = [
                    lib for lib in self._package_libs_matches[package] if lib.startswith(lib_name_base)]
                # If libraries with the same name have matched to the package
                if existed_lib:
                    if abs(probability - self._libs_matches[existed_lib[0]]) < 0.0001:
                        self._bind_lib_to_package(
                            lib_name, probability, package)
                    elif probability > self._libs_matches[existed_lib[0]]:
                        for lib in existed_lib:
                            del self._libs_matches[lib]
                            for _package in self._lib_packages_matches[lib]:
                                self._package_libs_matches[_package].remove(
                                    lib)
                            del self._lib_packages_matches[lib]

                        self._bind_lib_to_package(
                            lib_name, probability, package)

                else:
                    self._bind_lib_to_package(lib_name, probability, package)
            else:
                self._bind_lib_to_package(lib_name, probability, package)

            return True

        return False

    def _get_root_package(self, class_names):
        """Get the root package of the classes.

        Root package is the most common prefix of all the `class_names`

        Args:
            class_names (list): The name of classes.
        
        Returns:
            str: The root package of the class_names.
        """

        packages = [cn.split("/")[:-1] for cn in class_names]
        root_package = os.path.commonprefix(packages)

        return "/".join(root_package)

    def _get_relationship_between_classes(self, class_names, lib_name=None):
        """Get the sub call, interface and inheritance relationship between classes.
        
        Args:
            class_names (str): The name of classes.
            lib_name (str, optional): Defaults to None. If lib_name is given, this function will return the relationship in the library. Otherwise, the relationship in the app will be returned. 
        
        Returns:
            (list, dict, dict): The sub graph edges of method_calls, interfaces and superclasses.
        """

        if self.mode == MODE.ACCURATE:
            sub_call_graph_edges = self._get_method_calls_between_classes(
                class_names, lib_name)
            sub_interface_graph_dict = self._get_interfaces_between_classes(
                class_names, lib_name)
            sub_superclass_graph_dict = self._get_inheritance_between_classes(
                class_names, lib_name)

            return sub_call_graph_edges, sub_interface_graph_dict, sub_superclass_graph_dict
        else:
            return [], None, None

    def _get_method_calls_between_classes(self, class_names, lib_name=None):
        """Get the call (invocation) graph between classes.
        
        Args:
            class_names (str): The name of classes.
            lib_name (str, optional): Defaults to None. If lib_name is given, this function will return the relationship in the library. Otherwise, the relationship in the app will be returned. 
        
        Returns:
            list: The call (invocation) graph between class_names.
        """

        call_graph = self.LIB_RELATIONSHIP_GRAPHS[lib_name][0] if lib_name else self._call_graph
        method_calls = []

        for edge in call_graph.subgraph(class_names).edges():
            for method in call_graph[edge[0]][edge[1]]["method"]:
                call_info = edge + method
                method_calls.append(Method(*call_info))
                # method_calls.append(call_info)

        return method_calls

    def _get_interfaces_between_classes(self, class_names, lib_name=None):
        """Get the interface graph between classes.
        
        Args:
            class_names (str): The name of classes.
            lib_name (str, optional): Defaults to None. If lib_name is given, this function will return the relationship in the library. Otherwise, the relationship in the app will be returned. 
        
        Returns:
            list: The interface graph between classes.
        """

        interfaces_graph = self.LIB_RELATIONSHIP_GRAPHS[lib_name][1] if lib_name else self._interface_graph
        subgraph = interfaces_graph.subgraph(class_names)
        interfaces_dict = dict()

        for node in subgraph.nodes():
            if subgraph.neighbors(node):
                interfaces_dict[node] = subgraph.neighbors(node)

        return interfaces_dict

    def _get_inheritance_between_classes(self, class_names, lib_name=None):
        """Get the inheritance graph between classes.
        
        Args:
            class_names (str): The name of classes.
            lib_name (str, optional): Defaults to None. If lib_name is given, this function will return the relationship in the library. Otherwise, the relationship in the app will be returned. 
        
        Returns:
            list: The interface graph between classes.
        """

        superclass_graph = self.LIB_RELATIONSHIP_GRAPHS[lib_name][2] if lib_name else self._superclass_graph
        subgraph = superclass_graph.subgraph(class_names)
        superclass_dict = dict()

        for node in subgraph.nodes():
            if subgraph.neighbors(node):
                superclass_dict[node] = subgraph.neighbors(node)[0]

        return superclass_dict

    def _match_relationship_graph_for_lib(self, lib, lib_name, lib_class_num):
        LOGGER.debug("lib_name: %s", lib_name)

        lib_class_names = set(self._pmatch_lib_classes[lib])
        app_class_names = set(self._pmatch_app_classes[lib])
        potential_class_matches = set(self._pmatch_lib_app_classes[lib])

        lib_method_calls, lib_interfaces, lib_superclasses = self._get_relationship_between_classes(
            lib_class_names, lib_name)
        app_method_calls, app_interfaces, app_superclasses = self._get_relationship_between_classes(
            app_class_names)

        app_class_weights = dict()
        for class_name in app_class_names:
            app_class_weights[class_name] = 1.0 / lib_class_num + \
                0.0001 * len(self._classes_signatures[class_name])

        childless_packages = set()
        if self.consider_classes_repackaging:
            childless_packages = set(os.path.dirname(
                cn) for cn in app_class_names if not self._check_package_has_subpackage(os.path.dirname(cn)))

        LOGGER.debug("potential matches: %d, lib calls: %d, method_calls: %d", len(
            potential_class_matches), len(lib_method_calls), len(app_method_calls))

        return match(lib_classnames=lib_class_names,
                     app_classnames=app_class_names,
                     potential_class_matches=potential_class_matches,
                     lib_method_calls=lib_method_calls,
                     app_method_calls=app_method_calls,
                     app_class_weights=app_class_weights,
                     lib_class_parents=lib_superclasses,
                     app_class_parents=app_superclasses,
                     lib_class_interfaces=lib_interfaces,
                     app_class_interfaces=app_interfaces,
                     use_pkg_hierarchy=not self.consider_classes_repackaging,
                     assume_flattened_package=self.consider_classes_repackaging,
                     flattened_app_pkgs_allowed=childless_packages)

    def _match_libraries(self):
        self._get_possible_matches()

        library_matching_start = time.time()
        LOGGER.info("Start matching libraries ...")
        for lib in tqdm(self._pmatch_app_classes):
            # lib = "lib_name|root_package|class_num|sig_num|category|"
            [lib_name, root_package, class_num,
                signature_num, category, _] = lib.split("|")
            self._lib_info[lib_name] = [root_package, category]

            start_time = time.time()
            weight, matched_classes_pairs = self._match_relationship_graph_for_lib(
                lib, lib_name, int(class_num))
            end_time = time.time()

            LOGGER.debug("graph matching time: %fs",
                              end_time - start_time)

            matched_app_classes = set(pair[1]
                                      for pair in matched_classes_pairs)

            shrink_percentage = self._get_shrink_percentage(
                matched_app_classes, signature_num)

            LOGGER.debug("matched weight: %f", weight)
            LOGGER.debug("shrink percentage: %f", shrink_percentage)
            LOGGER.debug("matched classes pairs: %s", matched_classes_pairs)

            if shrink_percentage > self.shrink_threshold:
                matched_root_package = self._get_root_package(
                    matched_app_classes)
                self._check_package_lib_match(
                    lib_name, matched_root_package, matched_classes_pairs, int(class_num), int(signature_num))

        library_matching_end = time.time()

        LOGGER.info("Libraries matching finished. Duration: %fs", library_matching_end - library_matching_start)


    # LibID core methods (API)
    # ---------------------------------------------------------

    def get_libraries(self, lsh, mode=MODE.SCALABLE, repackage=False, LIB_RELATIONSHIP_GRAPHS=None, exclude_builtin=True):
        """Get all third party libraries used in this app.
        
        Args:
            lsh (MinHashLSH): Indexed Locality Sensitive Hashing (LSH) object.
            mode (<enum 'MODE'>, optional): Defaults to MODE.SCALABLE. The detection mode. Either MODE.ACCURATE or MODE.SCALABLE.
            repackage (bool, optional): Defaults to False. Should LibID consider classes repackaging?
            LIB_RELATIONSHIP_GRAPHS (dict, optional): Defaults to None. A dictionary of the library relation graphs. LIB_RELATIONSHIP_GRAPHS[lib_name] = (call_graph, interface_graph, inheritance graph).
            exclude_builtin (bool, optional): Defaults to True. Should LibID exclude builtin Android libraries?
        
        Returns:
            dict: Library matches.
        """

        self.LIB_RELATIONSHIP_GRAPHS = LIB_RELATIONSHIP_GRAPHS
        self.mode = mode
        self.consider_classes_repackaging = repackage
        self.shrink_threshold = config.SHRINK_THRESHOLD_ACCURATE if mode == MODE.ACCURATE else config.SHRINK_THRESHOLD_SCALABLE
        self.probability_threshold = config.PROBABILITY_THRESHOLD_ACCURATE if mode == MODE.ACCURATE else config.PROBABILITY_THRESHOLD_SCALABLE

        if not self._package_classes:
            self._build_packages_info()
            self._get_raw_classes_matches(lsh, exclude_builtin)

        if mode == MODE.ACCURATE:
            self.get_relationship_graphs(repackage)

        if not self._libs_matches:
            self._match_libraries()

        return self._libs_matches

    def get_classes(self):
        classes = []
        for dex in self.d:
            classes.extend(dex.get_classes())

        return classes

    def get_packages(self):
        if not self._package_classes:
            self._build_packages_info()

        return self._package_classes.keys()

    def get_package_classes(self):
        if not self._package_classes:
            self._build_packages_info()

        return self._package_classes

    def get_package_matches(self):
        return self._package_libs_matches


    # JSON export related methods
    # ---------------------------------------------------------

    def get_matched_libs_json_info(self):
        json_info = OrderedDict([('filename', self.filename),
                                 ('appID', self.appID),
                                 ('permissions', self.permissions),
                                 ('libraries', self._get_libs_matches_detail_info())
                                 ])

        return json_info

    def get_lib_classes_signatures_json_info(self):
        if not self._classes_signatures:
            self.get_classes_signatures()

        lib_name_version = os.path.splitext(
            os.path.basename(self.file_path))[0]
        category = self.file_path.split("/")[-2]
        root_package = os.path.dirname(
            os.path.commonprefix(self.classes_names))

        json_info = OrderedDict([('name', lib_name_version.split("_")[0]),
                                 ('version', "_".join(
                                     lib_name_version.split("_")[1:])),
                                 ('category', category),
                                 ('root_package', root_package),
                                 ('classes_num', len(self._classes_signatures)),
                                 ('classes_signatures', self._classes_signatures),
                                 ('classes_xref_tos', self._classes_xref_tos),
                                 ('classes_interfaces', self._classes_interfaces),
                                 ('classes_superclass', self._classes_superclass)
                                 ])

        return json_info

    def get_classes_signatures_json_info(self):
        if not self._classes_signatures:
            self.get_classes_signatures()

        json_info = OrderedDict([('filename', self.filename),
                                 ('appID', self.appID),
                                 ('permissions', self.permissions),
                                 ('classes_signatures', self._classes_signatures),
                                 ('classes_xref_tos', self._classes_xref_tos),
                                 ('classes_interfaces', self._classes_interfaces),
                                 ('classes_superclass', self._classes_superclass)
                                 ])

        return json_info

    def _get_libs_matches_detail_info(self):
        libs_matches_detail = []
        for lib in self._libs_matches:
            libname = lib.split("_")[0]
            version = "_".join(lib.split("_")[1:])

            root_package = list(self._lib_packages_matches[lib])
            rp_exist = self._lib_info[lib][0] in root_package

            existed_lib = [l for l in libs_matches_detail if l['name'] ==
                           libname and l['matched_root_package'] == root_package]

            if existed_lib:
                existed_lib[0]['version'].append(version)
                if self._lib_shrink_percentage[lib] > existed_lib[0]['shrink_percentage']:
                    existed_lib[0]['shrink_percentage'] = self._lib_shrink_percentage[lib]
            else:
                info_dict = OrderedDict([('name', libname),
                                         ('version', [version]),
                                         ('category',
                                          self._lib_info[lib][1]),
                                         ('root_package_exist', rp_exist),
                                         ('similarity',
                                          self._libs_matches[lib]),
                                         ('matched_root_package', root_package),
                                         ('shrink_percentage',
                                          self._lib_shrink_percentage[lib])
                                         ])
                libs_matches_detail.append(info_dict)

        return libs_matches_detail
