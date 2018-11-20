# @CreateTime: May 28, 2017 2:14 PM
# @Author: Stan Zhang
# @Contact: jz448@cl.cam.ac.uk
# @Last Modified By: Stan Zhang
# @Last Modified Time: Nov 7, 2018 2:14 PM
# @Description: Profiller for LibID

import json
import time
from itertools import izip, repeat
from multiprocessing import Pool
from os import makedirs, path

from datasketch import LeanMinHash, MinHash

from module.analyzer import LibAnalyzer
from module.config import LOGGER, LSH_PERM_NUM, MODE


# Helper methods
# ----------------------------------------------
def write_to_json(file_path, obj):
    path_dir = path.dirname(file_path)
    if not path.exists(path_dir):
        makedirs(path_dir)

    with open(file_path, 'wb') as fd:
        json_string = json.dumps(obj)
        fd.write(json_string)


# Profilling related methods
# ----------------------------------------------


def _profiling_binary(profiling_info):
    (file_path, output_dir, profile_type, overwrite) = profiling_info
    name = path.splitext(path.basename(file_path))[0] + ".json"

    json_file_path = path.join(output_dir, profile_type, name)
    if overwrite or not path.exists(json_file_path):
        try:
            analyzer = LibAnalyzer(file_path)

            json_info = analyzer.get_classes_signatures_json_info(
            ) if profile_type == "app" else analyzer.get_lib_classes_signatures_json_info(
            )
            write_to_json(json_file_path, json_info)
            LOGGER.info("The binary profile is stored at %s", json_file_path)
        except Exception, e:
            LOGGER.error("error: %s", e)
            return file_path
    else:
        LOGGER.error("The %s profile (%s) already exists. Use -w to overwrite",
                     profile_type, json_file_path)
        return file_path


def parallel_profiling_binaries(paths,
                                output_folder,
                                profile_type,
                                processes=1,
                                overwrite=False):
    """Profiling Android app/library binaries to JSON files.
    
    Args:
        paths (list): The list of binaries.
        output_folder (str): The folder to store profiles.
        profile_type (str): Either 'app' or 'lib'.
        processes (int, optional): Defaults to 1. The number of processes to use.
        overwrite (bool, optional): Defaults to False. Should LibID overwrite the binary profile if it exists?
    """

    start_time = time.time()

    if processes == 1:
        failed_binaries = map(
            _profiling_binary,
            izip(paths, repeat(output_folder), repeat(profile_type),
                 repeat(overwrite)))
    else:
        pool = Pool(processes=processes)
        failed_binaries = pool.map(
            _profiling_binary,
            izip(paths, repeat(output_folder), repeat(profile_type),
                 repeat(overwrite)))

    end_time = time.time()

    failed_binaries = [b for b in failed_binaries if b]

    LOGGER.info("Profiling time: %fs", end_time - start_time)
    LOGGER.info("Failed binaries: %s", failed_binaries)


# Profile loading related methods
# ----------------------------------------------


def _load_lib_profile(profile_path_n_mode_n_repackage):
    (profile_path, mode, repackage) = profile_path_n_mode_n_repackage

    analyzer = LibAnalyzer(profile_path)
    lib_name_version = "{}_{}".format(analyzer.lib_name, analyzer.lib_version)

    minhash_list = []
    relationship_graphs = None

    if len(analyzer.classes_names) > 4:
        if mode == MODE.ACCURATE:
            relationship_graphs = analyzer.get_relationship_graphs(repackage)

        classes_signatures = analyzer.get_classes_signatures()
        signature_set = set()
        lib_class_num = 0

        for class_name in classes_signatures:
            if classes_signatures[class_name]:
                signature_set.update(classes_signatures[class_name])
                lib_class_num += 1

        for class_name in classes_signatures:
            class_signatures = classes_signatures[class_name]

            if class_signatures:
                m = MinHash(num_perm=LSH_PERM_NUM)
                for signature in class_signatures:
                    m.update(signature.encode('utf8'))

                lm = LeanMinHash(m)
                key = "{}|{}|{}|{}|{}|->{}".format(
                    lib_name_version, analyzer.root_package, lib_class_num,
                    len(signature_set), analyzer.category, class_name)
                minhash_list.append((key, lm, len(class_signatures)))

    return (lib_name_version, minhash_list, relationship_graphs)


def parallel_load_libs_profile(lib_profiles,
                               mode=MODE.ACCURATE,
                               repackage=False,
                               processes=1):
    """Loading library profiles as a MinHash list and relation graphs.
    
    Args:
        lib_profiles (list): The list of library profiles.
        mode (<enum 'MODE'>, optional): Defaults to MODE.ACCURATE. The detection mode. Either MODE.ACCURATE or MODE.SCALABLE. See the paper for more details.
        repackage (bool, optional): Defaults to False. Should LibID consider classes repackaging? This should only be enabled if already know classes repackaging is applied. 
        processes (int, optional): Defaults to 1. The number of processes to use.
    
    Returns:
        tuple: (the minhash list, the relation graph dictionary)
    """

    LOGGER.info("Loading %d library profiles ...", len(lib_profiles))

    start_time = time.time()

    if processes == 1:
        results = map(_load_lib_profile,
                      izip(lib_profiles, repeat(mode), repeat(repackage)))
    else:
        pool = Pool(processes=processes)
        results = pool.map(_load_lib_profile,
                           izip(lib_profiles, repeat(mode), repeat(repackage)))

    end_time = time.time()

    LOGGER.info("Library profiles loaded. Duration: %fs",
                end_time - start_time)

    minhash_list = []
    lib_relationship_graphs_dict = dict()

    for result in results:
        minhash_list += result[1]
        if mode == MODE.ACCURATE:
            lib_relationship_graphs_dict[result[0]] = result[2]

    return (minhash_list, lib_relationship_graphs_dict)
