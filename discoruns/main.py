import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

import forensicstore
import tabulate

from discoruns import collect
from discoruns.wrapper.ac_wrapper import ArtifactCollectorWrapper

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        prog="discoruns",
        description="Extract persistence mechanisms from disc images or forensicstores."
    )

    parser.add_argument(
        '--format',
        help="Output format of the collected persistence mechanisms.",
        choices=['console', 'json'],
        dest='format',
        default="console"
    )
    parser.add_argument(
        "-v", "--verbose",
        help="Show logging messages.",
        dest='verbose',
        action="store_true",
        default=False
    )

    subparsers = parser.add_subparsers(title="subcommands", dest="subcommand", required=True)

    parser_image = subparsers.add_parser('image')
    parser_image.add_argument("image", metavar="IMAGE", help="Location of a disk image or a forensicstore.")

    parser_forensicstore = subparsers.add_parser('forensicstore')
    parser_forensicstore.add_argument("forensicstore", metavar="FORENSICSTORE", help="Location of a forensicstore.")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    start_time = time.time()

    if args.subcommand == "image":
        if not os.path.exists(args.image):
            logger.error("Image does not exist!")
            sys.exit(1)

        fstore_full_path = f"{Path(args.image).stem}.forensicstore"

        # Create new store
        try:
            store = forensicstore.new(fstore_full_path)
            store.close()
        except forensicstore.forensicstore.StoreExitsError:
            logger.error("Forensicstore does allready exist!")
            sys.exit(1)

        # Start extraction
        logger.info("Collecting artifacts. This might take a while...")
        ArtifactCollectorWrapper(args.image, fstore_full_path,
                                 f"{os.path.join(os.path.dirname(os.path.abspath(__file__)), 'artifacts')}",
                                 "WindowsPersistence").collect_artifacts()

    elif args.subcommand == "forensicstore":
        if not os.path.exists(args.forensicstore):
            logger.error("Forensicstore does not exist!")
            sys.exit(1)

        logger.info("Using an existing forensicstore.")
        fstore_full_path = args.forensicstore

    collected_mechanisms = collect(fstore_full_path)

    if args.format == "json":
        print(json.dumps(collected_mechanisms, indent=4))
    else:
        print(tabulate.tabulate(collected_mechanisms))
        print()
        print("Total found entries: " + str(len(collected_mechanisms)))
        print("Execution time: %.4s seconds" % (time.time() - start_time))


if __name__ == '__main__':
    main()
