import os
import pandas as pd

# Check if Prowler output file exist
path = os.getcwd()
for filename in os.listdir(path):
    root, ext = os.path.splitext(filename)
    try:
        if root.startswith('prowler-output') and ext == '.csv':
            print ("Found Prowler Output File, running GDPR Control Mapping")


            file = pd.read_csv(filename)
            add_column = file.insert(8, "GDPR SCF#", 'N/A')


            df = pd.DataFrame(file)
            #if df['TITLE_TEXT'].eq('[check11] Avoid the use of the root account').any():
            df.loc[df['TITLE_TEXT'] == '[check11] Avoid the use of the root account', 'GDPR SCF#'] = 'IAC-06'

            df.loc[df['TITLE_TEXT'] == '[check12] Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password', 'GDPR SCF#'] = 'IAC-06'





            output = file.to_csv('Prowler_with_GDPR_Mapping.csv')

    except FileNotFoundError:
        print ("No Prowler Output File Found")






