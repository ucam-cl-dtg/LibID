import logging
import logging.config
import os
import pickle
from datetime import datetime
from enum import Enum

LSH_PERM_NUM = 256
LSH_THRESHOLD = 0.8

SHRINK_THRESHOLD_ACCURATE = 0.1         # The minimum percentage of library classes needed to make a decision (LibID-A mode)
SHRINK_THRESHOLD_SCALABLE = 0.1         # The minimum percentage of library classes needed to make a decision (LibID-S mode)
SHRINK_MINIMUM_NUMBER = 5               # The minimum number of classes needed to make a decision
PROBABILITY_THRESHOLD_ACCURATE = 0.8    # The minimum percentage of app classes needed to make a decision (LibID-A mode)
PROBABILITY_THRESHOLD_SCALABLE = 0.8    # The minimum percentage of app classes needed to make a decision (LibID-S mode)

ANDROID_SDK_PATH = os.path.join(
    os.path.dirname(__file__), '../data/ANDROID_SDK_26.data')

DEX2JAR_PATH = os.path.join(
    os.path.dirname(__file__), '../dex2jar/d2j-jar2dex.sh')

MODE = Enum('MODE', 'SCALABLE ACCURATE')

with open(ANDROID_SDK_PATH, "rb") as fd:
    ANDROID_SDK_CLASSES = pickle.load(fd)

# Log related config
# -------------------------------------------------
LOG_FOLDER = os.path.join(os.path.dirname(__file__), '../data/log')

GENRERAL_LOG = os.path.join(LOG_FOLDER, "general",
                            datetime.now().strftime('LibID_%Y%m%d%H%M.log'))
MATCH_LOG = os.path.join(LOG_FOLDER, "match",
                         datetime.now().strftime('LibID_%Y%m%d%H%M.log'))

if not os.path.exists(os.path.dirname(GENRERAL_LOG)):
    os.makedirs(os.path.dirname(GENRERAL_LOG))

if not os.path.exists(os.path.dirname(MATCH_LOG)):
    os.makedirs(os.path.dirname(MATCH_LOG))

logging.config.fileConfig(
    os.path.join(os.path.dirname(__file__), 'logging.conf'),
    defaults={
        'general_log': GENRERAL_LOG,
        'match_log': MATCH_LOG
    })
    
LOGGER = logging.getLogger('console')
FILE_LOGGER = logging.getLogger('file')
