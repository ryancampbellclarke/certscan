import configparser


class CloudUpload:
    # Ensure that the license key is valid before scanning or else the discovery will be useless otherwise.
    @staticmethod
    def cloud_license_key_valid():
        config = configparser.ConfigParser()
        config.read('config.ini')
        license_key = config['DEFAULT']['LicenseKey']
        # TODO Use license key to hit validation endpoint on cloud API
        return True
