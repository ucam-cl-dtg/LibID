#!/usr/bin/env python2

# @CreateTime: Jun 7, 2017 9:07 AM
# @Author: Stan Zhang
# @Contact: jz448@cl.cam.ac.uk
# @Last Modified By: Stan Zhang
# @Last Modified Time: Nov 7, 2018 2:14 PM
# @Description: LibID

import argparse
import datetime
import subprocess
import time
from itertools import izip, repeat
from multiprocessing import Pool
from os import path

import glob2
from datasketch import MinHashLSHEnsemble

from module import profiler
from module.analyzer import LibAnalyzer
from module.config import (DEX2JAR_PATH, LOGGER, LSH_PERM_NUM, LSH_THRESHOLD,
                           MODE)

LSH = None
LIB_RELATIONSHIP_GRAPHS = dict()

# Helper methods
# ----------------------------------------------


def _get_output_path(file_path, output_folder):
    file_name = path.splitext(path.basename(file_path))[0]
    output_path = path.join(output_folder, file_name + ".json")

    return output_path


def _export_result_to_json(analyzer, output_path, start_time):
    json_info = analyzer.get_matched_libs_json_info()

    end_time = time.time()
    json_info["time"] = end_time - start_time
    profiler.write_to_json(output_path, json_info)

    LOGGER.info("The result of %s is stored at %s", path.basename(output_path),
                output_path)


# Loading related methods
# ----------------------------------------------


def load_LSH(lib_profiles, mode=MODE.ACCURATE, repackage=False,
             processes=None):
    """Load library profiles to an LSH object.
    
    Args:
        lib_profiles (list): The list of library profiles.
        mode (<enum 'MODE'>, optional): Defaults to MODE.ACCURATE. The detection mode. Either MODE.ACCURATE or MODE.SCALABLE. See the paper for more details.
        repackage (bool, optional): Defaults to False. Should LibID consider classes repackaging? This should only be enabled if already know classes repackaging is applied. 
        processes (int, optional): Defaults to None. The number of processes to use. If processes is None then the number returned by cpu_count() is used.
    """

    global LSH, LIB_RELATIONSHIP_GRAPHS

    weights = (0.5, 0.5) if repackage else (0.1, 0.9)
    LSH = MinHashLSHEnsemble(
        threshold=LSH_THRESHOLD,
        num_perm=LSH_PERM_NUM,
        num_part=32,
        weights=weights)

    (minhash_list,
     LIB_RELATIONSHIP_GRAPHS) = profiler.parallel_load_libs_profile(
         lib_profiles=lib_profiles,
         mode=mode,
         repackage=repackage,
         processes=processes)

    LOGGER.info("Start indexing LSH (this could take a while) ...")

    start_time = time.time()
    LSH.index(minhash_list)
    end_time = time.time()

    LOGGER.info("LSH indexed. Duration: %fs", end_time - start_time)


# Profiling related methods
# ----------------------------------------------


def _profile_apps(apk_files, output_folder=None, processes=1, overwrite=False):
    if apk_files:
        profiler.parallel_profiling_binaries(
            apk_files,
            output_folder,
            "app",
            processes=processes,
            overwrite=overwrite)


def _profile_libs(dex_files,
                  jar_files,
                  output_folder="profiles",
                  processes=None,
                  overwrite=False):
    # Convert jar file to dex file
    for f in jar_files:
        dex_file_path = path.join(
            path.dirname(f),
            path.basename(f)[:-4] + ".dex")

        if not path.exists(dex_file_path):
            LOGGER.info("Converting %s to %s ...", path.basename(f),
                        path.basename(dex_file_path))
            cmd = "{} -o {} {}".format(DEX2JAR_PATH, dex_file_path, f)

            try:
                subprocess.check_output(cmd, shell=True)
                LOGGER.info("Converted")

                dex_files.append(dex_file_path)
            except:
                LOGGER.error("Conversion failed")
                continue

    if dex_files:
        profiler.parallel_profiling_binaries(
            dex_files,
            output_folder,
            "lib",
            processes=processes,
            overwrite=overwrite)


def profile_binaries(base_path=None,
                     file_paths=None,
                     output_folder='profiles',
                     processes=None,
                     overwrite=False):
    """Profile app/library binaries to JSON files.

    Must provide either `base_path` or `file_paths`. 

    Args:
        base_path (str, optional): Defaults to None. The folder that contains app/library binaries.
        file_paths (list, optional): Defaults to None. The list of app/library binaries.
        output_folder (str, optional): Defaults to 'profiles'. The folder to store profiles.
        processes (int, optional): Defaults to None. The number of processes to use. If processes is None then the number returned by cpu_count() is used.
        overwrite (bool, optional): Defaults to False. Should LibID overwrite the output file if it exists?
    """

    if not file_paths:
        if base_path:
            apk_files = glob2.glob(path.join(base_path, "**/*.apk"))
            dex_files = glob2.glob(path.join(base_path, "**/*.dex"))
            jar_files = glob2.glob(path.join(base_path, "**/*.jar"))
        else:
            LOGGER.error("No valid folder or file path provided.")
    else:
        apk_files = [f for f in file_paths if f[-4:] == '.apk']
        dex_files = [f for f in file_paths if f[-4:] == '.dex']
        jar_files = [f for f in file_paths if f[-4:] == '.jar']

    _profile_apps(
        apk_files,
        output_folder=output_folder,
        processes=processes,
        overwrite=overwrite)
    _profile_libs(
        dex_files,
        jar_files,
        output_folder=output_folder,
        processes=processes,
        overwrite=overwrite)


# Searching related methods
# ----------------------------------------------


def _search_libs_in_app(profile_n_mode_n_output_n_repackage_n_exclude):
    global LSH

    (app_profile, mode, output_folder, repackage,
     exclude_builtin) = profile_n_mode_n_output_n_repackage_n_exclude

    output_path = _get_output_path(app_profile, output_folder)

    try:
        start_time = time.time()
        analyzer = LibAnalyzer(app_profile)
        analyzer.get_libraries(
            LSH,
            mode=mode,
            repackage=repackage,
            LIB_RELATIONSHIP_GRAPHS=LIB_RELATIONSHIP_GRAPHS,
            exclude_builtin=exclude_builtin)

        _export_result_to_json(analyzer, output_path, start_time)
    except Exception:
        LOGGER.exception("%s failed", app_profile)


def search_libs_in_apps(lib_folder=None,
                        lib_profiles=None,
                        app_folder=None,
                        app_profiles=None,
                        mode=MODE.ACCURATE,
                        overwrite=False,
                        output_folder='outputs',
                        repackage=False,
                        processes=None,
                        exclude_builtin=True):
    """Find if specified libraries are used in specified apps. Results will be stored in the `output_folder` as JSON files.

    Must provide either `lib_folder` or `lib_profiles`.

    Must provide either `app_folder` or `app_profiles`.

    Args:
        lib_folder (str, optional): Defaults to None. The folder that contains library binaries.
        lib_profiles (list, optional): Defaults to None. The list of library profiles.
        app_folder (str, optional): Defaults to None. The folder that contains app binaries.
        app_profiles (list, optional): Defaults to None. The list of app profiles.
        mode (<enum 'MODE'>, optional): Defaults to MODE.ACCURATE. The detection mode. Either MODE.ACCURATE or MODE.SCALABLE. See the paper for more details.
        overwrite (bool, optional): Defaults to False. Should LibID overwrite the output file if it exists?
        output_folder (str, optional): Defaults to 'outputs'. The folder to store results.
        repackage (bool, optional): Defaults to False. Should LibID consider classes repackaging? This should only be enabled if already know classes repackaging is applied. 
        processes (int, optional): Defaults to None. The number of processes to use. If processes is None then the number returned by cpu_count() is used.
        exclude_builtin (bool, optional): Defaults to True. Should LibID exclude builtin Android libraries (e.g., Android Support V14)? Enable this option can speed up the detection process.
    """

    if not app_profiles:
        if app_folder:
            app_profiles = glob2.glob(path.join(app_folder, "**/*.json"))

    if not lib_profiles:
        if lib_folder:
            lib_profiles = glob2.glob(path.join(lib_folder, "**/*.json"))

    if not overwrite:
        original_profile_num = len(app_profiles)
        app_profiles = [
            fp for fp in app_profiles
            if not path.exists(_get_output_path(fp, output_folder))
        ]

        ignored_profile_num = original_profile_num - len(app_profiles)
        if ignored_profile_num:
            LOGGER.warning(
                "Ignored %i app profiles because the output file already exist. Use -w to overwrite",
                ignored_profile_num)

    if app_profiles and lib_profiles:
        start_time = time.time()
        load_LSH(
            lib_profiles, mode=mode, repackage=repackage, processes=processes)

        if processes == 1:
            map(
                _search_libs_in_app,
                izip(app_profiles, repeat(mode), repeat(output_folder),
                     repeat(repackage), repeat(exclude_builtin)))
        else:
            pool = Pool(processes=None)
            pool.map(
                _search_libs_in_app,
                izip(app_profiles, repeat(mode), repeat(output_folder),
                     repeat(repackage), repeat(exclude_builtin)))

        end_time = time.time()

        LOGGER.info("Finished. Numer of apps: %d, date: %s, duration: %fs",
                    len(app_profiles),
                    datetime.datetime.now().ctime(), end_time - start_time)


# Command line arguments parser
# ----------------------------------------------


def parse_arguments():
    parser = argparse.ArgumentParser(description='Process some integers')
    subparsers = parser.add_subparsers(
        help='sub-command help', dest='subparser_name')

    parser_profiling = subparsers.add_parser(
        'profile', help='profiling the app/library binaries')
    parser_profiling.add_argument(
        '-o',
        metavar='FOLDER',
        type=str,
        default='profiles',
        help='specify output folder')
    parser_profiling.add_argument(
        '-w',
        help='overwrite the output file if it exists',
        action='store_true')
    parser_profiling.add_argument(
        '-p',
        metavar='N',
        type=int,
        default=1,
        help='the number of processes to use [default: 1]')
    parser_profiling.add_argument(
        '-v', help='show debug information', action='store_true')

    group = parser_profiling.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-f',
        metavar='FILE',
        type=str,
        nargs='+',
        help='the app/library binaries')
    group.add_argument(
        '-d',
        metavar='FOLDER',
        type=str,
        help='the folder that contains app/library binaries')

    parser_detection = subparsers.add_parser(
        'detect', help='detect whether the library is used in the app')
    parser_detection.add_argument(
        '-o',
        metavar='FOLDER',
        type=str,
        default='outputs',
        help='specify output folder')
    parser_detection.add_argument(
        '-w',
        help='overwrite the output file if it exists',
        action='store_true')
    parser_detection.add_argument(
        '-b',
        help='considering build-in Android libraries',
        action='store_true')
    parser_detection.add_argument(
        '-p',
        metavar='N',
        type=int,
        default=None,
        help=
        'the number of processes to use [default: the number of CPUs in the system]'
    )
    parser_detection.add_argument(
        '-s',
        help='run program in Lib-S mode [default: LibID-A mode]',
        action='store_true')
    parser_detection.add_argument(
        '-r', help='consider classes repackaging', action='store_true')
    parser_detection.add_argument(
        '-v', help='show debug information', action='store_true')

    group = parser_detection.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-af', metavar='FILE', type=str, nargs='+', help='the app profiles')
    group.add_argument(
        '-ad',
        metavar='FOLDER',
        type=str,
        help='the folder that contains app profiles')

    group = parser_detection.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-lf',
        metavar='FILE',
        type=str,
        nargs='+',
        help='the library profiles')
    group.add_argument(
        '-ld',
        metavar='FOLDER',
        type=str,
        help='the folder that contains library profiles')

    return parser.parse_args()


if __name__ == '__main__':

    args = parse_arguments()

    if args.v:
        LOGGER.setLevel('DEBUG')
    else:
        LOGGER.setLevel('INFO')

    LOGGER.debug("args: %s", args)

    if args.subparser_name == 'profile':
        profile_binaries(
            base_path=args.d,
            file_paths=args.f,
            output_folder=args.o,
            processes=args.p,
            overwrite=args.w)
    else:
        search_libs_in_apps(
            lib_folder=args.ld,
            lib_profiles=args.lf,
            app_folder=args.ad,
            app_profiles=args.af,
            mode=MODE.SCALABLE if args.s else MODE.ACCURATE,
            overwrite=args.w,
            output_folder=args.o,
            repackage=args.r,
            processes=args.p,
            exclude_builtin=not args.b)
