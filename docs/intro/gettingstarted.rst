Features
----------------------

LibID is a a novel third-party Android library detection tool that can reliably identify the library version used in Android apps given the library and app binaries. LIBID is resilient to common code obfuscation techniques, including:

* Identifier renaming
* Code shrinking
* Control-flow randomization
* Package modification


Installation
----------------------------------

LibID uses Python 2.7.x. Dependencies can be installed by:

.. code-block:: bash

    pip install -r requirements.txt


In addition, LibID uses `Gurobi Optimizer <http://www.gurobi.com/index>`_ to solve the BIP (binary integer programming) problem. For researchers, a free academic license can be requested from the `Gurobi website <https://user.gurobi.com/download/licenses/free-academic>`_.

Usage
--------------------------------

To use LibID, users must first use the `profile` subcommand to generate app and library profiles from their binaries. Then, users can use the `detect` subcommand to detect if a library is used in an app.

Library Profiling
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: none

    $ ./LibID.py profile -h
    usage: LibID.py profile [-h] [-o FOLDER] [-w] [-p N] [-v]
                            (-f FILE [FILE ...] | -d FOLDER)

    optional arguments:
    -h, --help          show this help message and exit
    -o FOLDER           specify output folder
    -w                  overwrite the output file if it exists
    -p N                the number of processes to use [default: the number of CPUs in the system]
    -v                  show debug information
    -f FILE [FILE ...]  the app/library binaries
    -d FOLDER           the folder that contains app/library binaries

Profiling Android apps (\*.apk):

.. code-block:: none

    $ ./LibID.py profile -f app1.apk app2.apk ...

Profiling thrid-party Android libraries (\*.jar | \*.dex):

.. code-block:: none

    $ ./LibID.py profile -f lib1.jar lib2.jar ...


Profiling all related files (\*.apk | \*.jar | \*.dex) inside a directory:

.. code-block:: none

    $ ./LibID.py profile -d apps

The generated profiles will be stored as .json files.


Library Detection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: none

    $ ./LibID.py detect -h
    usage: LibID.py detect [-h] [-o FOLDER] [-w] [-b] [-p N] [-s] [-r] [-v]
                        (-af FILE [FILE ...] | -ad FOLDER)
                        (-lf FILE [FILE ...] | -ld FOLDER)

    optional arguments:
    -h, --help           show this help message and exit
    -o FOLDER            specify output folder
    -w                   overwrite the output file if it exists
    -b                   considering build-in Android libraries
    -p N                 the number of processes to use [default: the number of CPUs in the system]
    -A                   run program in Lib-A mode [default: LibID-S mode]
    -r                   consider classes repackaging
    -v                   show debug information
    -af FILE [FILE ...]  the app profiles
    -ad FOLDER           the folder that contains app profiles
    -lf FILE [FILE ...]  the library profiles
    -ld FOLDER           the folder that contains library profiles

Detect if specified apps use specified libraries:

.. code-block:: none

    $ ./LibID.py detect -af app1.json app2.json -lf lib1.json lib2.json lib3.json

Detect if apps in directory use libraries in a directory:

.. code-block:: none

    $ ./LibID.py detect -ad profiles/app -ld profiles/lib


Parameter Tuning
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The parameters of LibID can be found in the module/config.py file. In particular, users can tweak the following parameters to achieve better performance.

.. code-block:: python

    LSH_PERM_NUM = 256
    LSH_THRESHOLD = 0.8

    SHRINK_THRESHOLD_ACCURATE = 0.1         # The minimum percentage of library classes needed to make a decision (LibID-A mode)
    SHRINK_THRESHOLD_SCALABLE = 0.1         # The minimum percentage of library classes needed to make a decision (LibID-S mode)
    SHRINK_MINIMUM_NUMBER = 5               # The minimum number of classes needed to make a decision
    PROBABILITY_THRESHOLD_ACCURATE = 0.8    # The minimum percentage of app classes needed to make a decision (LibID-A mode)
    PROBABILITY_THRESHOLD_SCALABLE = 0.8    # The minimum percentage of app classes needed to make a decision (LibID-S mode)


Example
--------------------------------

Run the `example/init.sh` script to download the demo app and library binaries from FDroid and Maven.

.. code-block:: bash

    $ ./example/init.sh


Run the following command to profile the binaries:

.. code-block:: none

    $ ./LibID.py profile -d example


Run the following command to detect the correct version of OkHttp library used in the app:

.. code-block:: none

    $ ./LibID.py detect -ad profiles/app -ld profiles/lib


The result is stored under the `outputs` folder as a .json file:

.. code-block:: json

    $ python -m json.tool outputs/com.example.root.analyticaltranslator_6.json
    {
        "appID": "com.example.root.analyticaltranslator",
        "filename": "com.example.root.analyticaltranslator_6.apk",
        "libraries": [
            {
                "category": "example",
                "matched_root_package": [
                    "Lcom/squareup/okhttp"
                ],
                "name": "okhttp",
                "root_package_exist": true,
                "shrink_percentage": 1.0,
                "similarity": 1.0,
                "version": [
                    "2.3.0"
                ]
            }
        ],
        "permissions": [
            "android.permission.INTERNET"
        ],
        "time": 3.760045051574707
    }


