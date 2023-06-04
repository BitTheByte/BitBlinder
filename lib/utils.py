import json
import os

class URL(object):
    PARAM_URL = 0
    PARAM_BODY = 1
    PARAM_COOKIE = 2
    PARAM_XML = 3
    PARAM_XML_ATTR = 4
    PARAM_MULTIPART_ATTR = 5
    PARAM_JSON = 6

class Helpers(object):

    def get_payloads(self):

        return (self.payloads_list.getText().replace(" ","%20")).split("\n")

    def save_settings(self, evnt):

        config = {
            'Randomize': 0,
            'Payloads': [],
            'isEnabled': self.enable.isSelected(),
        }
        config['Randomize'] = self.randomize.isSelected()

        for payload in self.get_payloads():
            config['Payloads'].append(payload)

        with open("./config.json", "w") as f:
            f.write(json.dumps(config))
        print("[~] Settings saved")
        return

    def load_settings(self):

        # Check if there's saved config if true then load it
        if os.path.isfile('./config.json'):

            with open("./config.json", "r") as f:
                config = json.loads(f.read())
            self.enable.setSelected(config['isEnabled'])
            self.randomize.setSelected(config['Randomize'])
            self.payloads_list.setText('\n'.join(config['Payloads']))

            print("[~] Settings loaded")

        return
