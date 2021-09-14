import argparse
import subprocess
from create_instance import CreateInstance
from set_configuration import ConfigurationSet
from collect_test_files import CollectTestFiles
import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'attack_range'))
from attack_range.modules.TerraformController import TerraformController
from attack_range.modules import splunk_sdk
from attack_range.modules import splunk_sdk
from attack_range import attack_range

class ExecuteDetection:

    def __init__(self):
        self.test_args = self.get_args()

    def get_args(self):
        """
            Get arguments from CLI
        """
        arg_parser = argparse.ArgumentParser(
            description='parse args for executing test cases\n')

        arg_parser.add_argument('-sv', '--splunk-version',
                                help="Splunk version of Splunk Enterprise", default="8.1.2")
        arg_parser.add_argument('-tft', '--test-file-type',
                                help="Comma separated values for test file type")
        # arg_parser.add_argument("-tf", "--test_files",
        #                         type=str, help='comma delimited list relative path of the test files')
        arg_parser.add_argument("-al", "--app_list",
                                type=str, help='comma delimited list for apps',
                                default="aws_app,aws_ta,aws_content,app_ess,o_365,escu")

        arg_parser.add_argument("-c", "--config", required=False, default="attack_range/attack_range.conf",
                            help="path to the configuration file of the attack range")
        arg_parser.add_argument("-v", "--version", default=False, action="version", version="version: {0}".format(1),
                            help="shows current attack_range version")

        # Test Arguments
        arg_parser.add_argument("-tf", "--test_files",
                                 type=str, default="../security_content/tests/cloud/aws_detect_users_creating_keys_with_encrypt_policy_without_mfa.test.yml", help='comma delimited list relative path of the test files')
        arg_parser.add_argument("-tbd", "--test_build_destroy", required=False, default=False,
                                 action="store_true",
                                 help='builds a attack_range, then runs the test files and finally destroy the range in one shot operation.')
        arg_parser.add_argument("-tdd", "--test_delete_data", required=False, default=False,
                                 action="store_true", help='delete the replayed attack data after detection test.')
        arg_parser.set_defaults(func=attack_range.test, test_build_destroy=False)
        # arg_parser.add_argument("-pkp", "--private-key-path",
        #                         type=str, help='provide private key path')
        return arg_parser.parse_args()

    def run_security_content_detections(self, test_file_name):
        """
            Run security content detections
        """
        run_detection_command = f"cd .. && python3 attack_range.py test -tf {test_file_name}"
        print(run_detection_command)
        # output, err = subprocess.Popen(
        #     run_detection_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        #     universal_newlines=True, executable="/bin/bash").communicate()
        self.test_args.test_files = test_file_name
        print(self.test_args.test_files)
        attack_range.test(self.test_args)

    def run_tests(self):
        """
            Run test cases for security content 
        """
        # Create a splunk 
        print("Splunk instance creation started")
        # CreateInstance().create_splunk_instance(splunk_version=self.test_args.splunk_version,
        #                                         app_list=self.test_args.app_list.split(","))

        # Set Configuration variable
        print("set config variable in conf file")
        ConfigurationSet().set_config_variable()

        # Check for test files
        if self.test_args.test_file_type:
            # Collect all test files
            test_file_names = CollectTestFiles().collect_all_files(
                detection_types=self.test_args.test_file_type.split(","))
            print("successfully Collected test file names from detection types")
        elif self.test_args.test_files:
            # set test file names from -tf parameter 
            test_file_names = self.test_args.test_files
        else:
            print("Must need to provide parameter from test_files or test_file_type")
            raise Exception("Must need to provide parameter from test_files or test_file_type")

        # Run detections
        self.run_security_content_detections(test_file_names)


def main():
    """
        Execute testcases for security content
    """
    detections = ExecuteDetection()
    detections.run_tests()


if __name__ == "__main__":
    main()