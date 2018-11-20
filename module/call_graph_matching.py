import itertools
from collections import namedtuple

from gurobipy import GRB, LinExpr, Model, and_

from module.config import LOGGER

ROOT_PKG = '<ROOT>'

Method = namedtuple(
    'Method', ['class1', 'class2', 'parameters1', 'parameters2', 'count'])


def get_method_matching_candidates(lib_method_calls, app_method_calls):
    res1 = itertools.product(lib_method_calls, app_method_calls)
    res2 = [(r[0], r[1], i) for i, r in enumerate(res1) if r[0].parameters1 ==
            r[1].parameters1 and r[0].parameters2 == r[1].parameters2 and r[0].count >= r[1].count]
    return res2


def match(lib_classnames, app_classnames, potential_class_matches, lib_method_calls, app_method_calls, app_class_weights, lib_class_parents=None, app_class_parents=None,
          lib_class_interfaces=None, app_class_interfaces=None, use_pkg_hierarchy=True, assume_flattened_package=False,
          flattened_app_pkgs_allowed=None, use_call_graph_constraints=True):

    m = Model("")

    # If the log level is DEBUG
    if LOGGER.getEffectiveLevel() == 10:
        LOGGER.debug('%d lib classes, %d app classes', len(lib_classnames), len(app_classnames))
        LOGGER.debug('%d lib methods, %d app methods', len(lib_method_calls), len(app_method_calls))
    else:
        m.setParam('OutputFlag', False)

    class_match_vars = {}
    lib_class_match_count_exprs = {}
    app_class_match_count_exprs = {}
    for pcm in potential_class_matches:
        class_match_vars[pcm] = m.addVar(vtype=GRB.BINARY)
        (lib_class, app_class) = pcm

        if lib_class not in lib_class_match_count_exprs:
            lib_class_match_count_exprs[lib_class] = LinExpr(0)
        lib_class_match_count_exprs[lib_class] += class_match_vars[pcm]

        if app_class not in app_class_match_count_exprs:
            app_class_match_count_exprs[app_class] = LinExpr(0)
        app_class_match_count_exprs[app_class] += class_match_vars[pcm]

    for expr in lib_class_match_count_exprs.itervalues():
        m.addConstr(expr <= 1)

    for expr in app_class_match_count_exprs.itervalues():
        m.addConstr(expr <= 1)

    app_class_used_vars = {}
    for app_class in app_classnames:
        app_class_used_vars[app_class] = m.addVar(vtype=GRB.BINARY)
        if app_class in app_class_match_count_exprs:
            m.addConstr(app_class_used_vars[app_class]
                        == app_class_match_count_exprs[app_class])
        else:
            m.addConstr(app_class_used_vars[app_class] == 0)

    LOGGER.debug('Method matching...')

    methods_matched_total_expr = LinExpr(0)
    if use_call_graph_constraints:
        method_matching_candidates = [cand for cand in get_method_matching_candidates(
            lib_method_calls, app_method_calls)]

        lib_method_match_count_exprs = {}
        app_method_match_count_exprs = {}

        for lib_method_call in lib_method_calls:
            lib_method_match_count_exprs[lib_method_call] = LinExpr(0)

        for app_method_call in app_method_calls:
            app_method_match_count_exprs[app_method_call] = LinExpr(0)

        method_matching_vars = {}
        for mm in method_matching_candidates:
            lib_method_call = mm[0]
            app_method_call = mm[1]
            lib_app_class1 = (lib_method_call.class1, app_method_call.class1)
            lib_app_class2 = (lib_method_call.class2, app_method_call.class2)
            if lib_app_class1 in class_match_vars and lib_app_class2 in class_match_vars:
                method_matching_vars[mm] = m.addVar(vtype=GRB.BINARY)
                m.addConstr(
                    method_matching_vars[mm] <= class_match_vars[lib_app_class1])
                m.addConstr(
                    method_matching_vars[mm] <= class_match_vars[lib_app_class2])
                
                lib_method_match_count_exprs[lib_method_call] += method_matching_vars[mm]
                app_method_match_count_exprs[app_method_call] += method_matching_vars[mm]

                methods_matched_total_expr += 1 * method_matching_vars[mm]

        LOGGER.debug('Done')

        for expr in lib_method_match_count_exprs.itervalues():
            m.addConstr(expr <= 1)

        for app_method_call, expr in app_method_match_count_exprs.iteritems():
            app_method_class1 = app_method_call.class1
            app_method_class2 = app_method_call.class2
            tmp = m.addVar(vtype=GRB.BINARY)
            m.addConstr(tmp == and_(
                app_class_used_vars[app_method_class1], app_class_used_vars[app_method_class2]))
            m.addConstr(expr == tmp)

    if use_pkg_hierarchy:
        lib_pkg_parent_dict = {}
        lib_class_pkg_dict = {}
        app_pkg_parent_dict = {}
        app_class_pkg_dict = {}
        process_class_hierarchy(
            lib_classnames, lib_pkg_parent_dict, lib_class_pkg_dict, ROOT_PKG)
        process_class_hierarchy(
            app_classnames, app_pkg_parent_dict, app_class_pkg_dict, ROOT_PKG)

        LOGGER.debug(lib_pkg_parent_dict)
        LOGGER.debug(app_pkg_parent_dict)
        LOGGER.debug(lib_class_pkg_dict)
        LOGGER.debug(app_class_pkg_dict)

        lib_pkg_match_cnt_exprs = {}
        app_pkg_match_cnt_exprs = {}

        all_lib_pkgs = list(lib_pkg_parent_dict.keys()) + [ROOT_PKG]
        all_app_pkgs = list(app_pkg_parent_dict.keys()) + [ROOT_PKG]

        LOGGER.debug('All lib packages: %s', all_lib_pkgs)
        LOGGER.debug('All app packages: %s', all_app_pkgs)

        potential_package_matches = list(
            itertools.product(all_lib_pkgs, all_app_pkgs))

        package_matches_vars = {}
        for (lib_pkg, app_pkg) in potential_package_matches:
            match_var = m.addVar(vtype=GRB.BINARY, name=(
                '%s/%s' % (lib_pkg, app_pkg)))
            package_matches_vars[(lib_pkg, app_pkg)] = match_var

            if lib_pkg not in lib_pkg_match_cnt_exprs:
                lib_pkg_match_cnt_exprs[lib_pkg] = LinExpr(0)
            lib_pkg_match_cnt_exprs[lib_pkg] += match_var

            if app_pkg not in app_pkg_match_cnt_exprs:
                app_pkg_match_cnt_exprs[app_pkg] = LinExpr(0)
            app_pkg_match_cnt_exprs[app_pkg] += match_var

        # Every lib package can be matched to at most one app package
        for expr in lib_pkg_match_cnt_exprs.itervalues():
            m.addConstr(expr <= 1)

        # Every app package can be matched to at most one lib package
        for expr in app_pkg_match_cnt_exprs.itervalues():
            m.addConstr(expr <= 1)

        # Packages can only match if their parent packages match too
        for (lib_pkg, app_pkg) in potential_package_matches:
            if lib_pkg == ROOT_PKG or app_pkg == ROOT_PKG:
                continue
            lib_parent_pkg = lib_pkg_parent_dict[lib_pkg]
            app_parent_pkg = app_pkg_parent_dict[app_pkg]
            match_var = package_matches_vars[(lib_pkg, app_pkg)]
            if (lib_parent_pkg, app_parent_pkg) in package_matches_vars:
                parent_match_var = package_matches_vars[(
                    lib_parent_pkg, app_parent_pkg)]
                m.addConstr(match_var <= parent_match_var)
            else:
                m.addConstr(match_var == 0)

        # Classes can only match if their packages also match
        for pcm in potential_class_matches:
            (lib_class, app_class) = pcm
            lib_class_pkg = lib_class_pkg_dict[lib_class]
            app_class_pkg = app_class_pkg_dict[app_class]
            ppm = (lib_class_pkg, app_class_pkg)

            if ppm in potential_package_matches:
                m.addConstr(class_match_vars[pcm] <= package_matches_vars[ppm])
            else:
                m.addConstr(class_match_vars[pcm] == 0)

    elif assume_flattened_package:

        app_pkg_parent_dict = {}
        app_class_pkg_dict = {}
        process_class_hierarchy(
            app_classnames, app_pkg_parent_dict, app_class_pkg_dict, ROOT_PKG)

        app_pkg_active_vars = {}
        active_pkgs_cnt_expr = LinExpr(0)

        if flattened_app_pkgs_allowed is None:
            flattened_app_pkgs_allowed = app_pkg_parent_dict.keys()
        else:
            flattened_app_pkgs_allowed = ['/' + pkg for pkg in flattened_app_pkgs_allowed]

        for pkg in flattened_app_pkgs_allowed:
            app_pkg_active_vars[pkg] = m.addVar(vtype=GRB.BINARY, name=('%s' % pkg))
            active_pkgs_cnt_expr += app_pkg_active_vars[pkg]

        m.addConstr(active_pkgs_cnt_expr <= 1)

        for pcm in potential_class_matches:
            (lib_class, app_class) = pcm
            app_class_pkg = app_class_pkg_dict[app_class]

            if app_class_pkg in app_pkg_active_vars:
                m.addConstr(class_match_vars[pcm] <= app_pkg_active_vars[app_class_pkg])
            else:
                m.addConstr(class_match_vars[pcm] == 0)

    app_parents_and_interf_matched_expr = LinExpr(0)

    if lib_class_parents:
        for pcm in potential_class_matches:
            (lib_class, app_class) = pcm
            parent_lib = lib_class_parents[lib_class] if lib_class in lib_class_parents else None
            parent_app = app_class_parents[app_class] if app_class in app_class_parents else None
            if parent_lib:
                if parent_app:
                    parents_match = (parent_lib, parent_app)
                    if parents_match in class_match_vars.keys():
                        m.addConstr(
                            class_match_vars[pcm] <= class_match_vars[parents_match])
                    else:
                        m.addConstr(class_match_vars[pcm] == 0)
                else:
                    m.addConstr(class_match_vars[pcm] == 0)
            else:
                if parent_app:
                    m.addConstr(1 - class_match_vars[pcm] >= app_class_match_count_exprs[parent_app])

            # Interface matching

            if lib_class_interfaces:
                interfaces_lib_class = lib_class_interfaces[lib_class] if lib_class in lib_class_interfaces else []
                interfaces_app_class = app_class_interfaces[app_class] if app_class in app_class_interfaces else []

                matched_interfaces_expr = LinExpr(0)
                for lib_interface in interfaces_lib_class:
                    for app_interface in interfaces_app_class:
                        interfaces_match = (lib_interface, app_interface)
                        if interfaces_match in class_match_vars:
                            matched_interfaces_expr += class_match_vars[interfaces_match]

                matched_lib_interfaces_expr = LinExpr(0)
                matched_app_interfaces_expr = LinExpr(0)
                for lib_interface in interfaces_lib_class:
                    if lib_interface in lib_class_match_count_exprs:
                        matched_lib_interfaces_expr += lib_class_match_count_exprs[lib_interface]
                for app_interface in interfaces_app_class:
                    if app_interface in app_class_match_count_exprs:
                        matched_app_interfaces_expr += app_class_match_count_exprs[app_interface]

                m.addConstr(2 * matched_interfaces_expr ==
                            matched_app_interfaces_expr + matched_lib_interfaces_expr)

        for app_class, app_class_parent in app_class_parents.iteritems():
            if app_class in app_class_used_vars and app_class_parent in app_class_used_vars:
                app_class_and_parent_matched = m.addVar(vtype=GRB.BINARY)
                m.addConstr(app_class_used_vars[app_class] >= app_class_and_parent_matched)
                m.addConstr(app_class_used_vars[app_class_parent] >= app_class_and_parent_matched)
                app_parents_and_interf_matched_expr += app_class_and_parent_matched

        if app_class_interfaces:
            for app_class, app_class_interfaces in app_class_interfaces.iteritems():
                for interface in app_class_interfaces:
                    if app_class in app_class_used_vars and interface in app_class_used_vars:
                        app_class_and_interface_matched = m.addVar(vtype=GRB.BINARY)
                        m.addConstr(app_class_used_vars[app_class] >= app_class_and_interface_matched)
                        m.addConstr(app_class_used_vars[interface] >= app_class_and_interface_matched)
                        app_parents_and_interf_matched_expr += app_class_and_interface_matched

    objective_expr = LinExpr(0)

    if use_call_graph_constraints:
        objective_expr += 0.0001 * methods_matched_total_expr + 0.0001 * app_parents_and_interf_matched_expr

    for app_class in app_classnames:
        weight = app_class_weights[app_class]
        objective_expr += weight * app_class_used_vars[app_class]
    m.setObjective(objective_expr, GRB.MAXIMIZE)

    LOGGER.debug('Optimizing...')

    m.optimize()

    matched_app_classes = set()
    class_matches = set()
    for pcm in potential_class_matches:
        if class_match_vars[pcm].x > 0.5:
            class_matches.add(pcm)
            matched_app_classes.add(pcm[1])

    LOGGER.debug('Done')
    LOGGER.debug('Class matches:')

    # If the log level is DEBUG
    if LOGGER.getEffectiveLevel() == 10:

        unmatched_lib_classes = set(lib_classnames)
        unmatched_app_classes = set(app_classnames)

        class_match_cnt = 0
        for pcm in potential_class_matches:
            if class_match_vars[pcm].x > 0.5:
                class_match_cnt += 1
                if pcm[0] != pcm[1]:
                    LOGGER.debug('Potentially wrong match: %s / %s' % pcm)
                    LOGGER.debug('Lib class methods: ')
                    for lm in lib_method_calls:
                        if lm[0] == pcm[0] or lm[1] == pcm[0]:
                            LOGGER.debug(lm)
                    LOGGER.debug('App class methods: ')
                    for am in app_method_calls:
                        if am[0] == pcm[1] or am[1] == pcm[1]:
                            LOGGER.debug(am)

                if pcm[0] in lib_classnames:
                    unmatched_lib_classes.remove(pcm[0])
                else:
                    LOGGER.debug('Missing lib class: %s' % pcm[0])
                if pcm[1] in app_classnames:
                    unmatched_app_classes.remove(pcm[1])
                else:
                    LOGGER.debug('Missing lib class: %s' % pcm[1])
        LOGGER.debug('%d classes matched', class_match_cnt)
        LOGGER.debug('Unmatched lib classes:')
        for cl in unmatched_lib_classes:
            LOGGER.debug(cl)

        LOGGER.debug('Unmatched app classes:')
        for cl in unmatched_app_classes:
            LOGGER.debug(cl)

        if use_call_graph_constraints:
            LOGGER.debug('Method matches:')
            method_match_cnt = 0
            for mm in method_matching_vars.keys():
                if method_matching_vars[mm].x > 0.5:
                    LOGGER.debug(mm)
                    method_match_cnt += 1

            LOGGER.debug('%d methods matched', method_match_cnt)

        if use_pkg_hierarchy:
            LOGGER.debug('Package matches:')
            package_match_cnt = 0
            for pm in package_matches_vars.keys():
                if package_matches_vars[pm].x > 0.5:
                    LOGGER.debug(pm)
                    package_match_cnt += 1
            LOGGER.debug('%d packages matched', package_match_cnt)

        LOGGER.debug('Active packages:')
        if assume_flattened_package:
            for pkg in flattened_app_pkgs_allowed:
                LOGGER.debug(pkg, app_pkg_active_vars[pkg].x)

        LOGGER.debug('Objective value: %0.4f', m.objval)

    return (m.objval, class_matches)


def process_class_hierarchy(classnames, parent_pkg_dict, class_pkg_dict, root):
    for full_classname in classnames:
        curr_pkg = ''
        for token in full_classname.rstrip().split('/'):
            if token.endswith(';'):
                class_pkg_dict[full_classname] = curr_pkg if curr_pkg else root
                break
            else:
                parent_pkg_dict[curr_pkg + "/" +
                                token] = curr_pkg if curr_pkg else root
                curr_pkg += "/" + token
