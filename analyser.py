import pandas as pd    
from collections import defaultdict

def loadCSV(filename): #Opens the test csv and loads it into a DataFrame
    
    df = pd.read_csv(filename)

    return df

def analyseData(df):

    failed_attempts = defaultdict(int)
    not_found_attempts = defaultdict(int)
    total_attempts = defaultdict(int)

    for _, row in df.iterrows():

        ip = row["ip"]
        status = int(row["status"])

        total_attempts[ip] += 1

        if status in [401, 403]:

            failed_attempts[ip] += 1

        elif status == 404:

            not_found_attempts[ip] += 1

    return failed_attempts, not_found_attempts, total_attempts


def createReport(failed, not_found, total):

    print("=== SUSPICIOUS ACTIVITY ===")

    for ip in total:

        if failed[ip] >= 5:
            print(f"[!] {ip} - {failed[ip]} failed login attempts")
        
        elif not_found[ip] >= 10:
            print(f"[!] {ip} - {not_found[ip]} 404 errors - (potential scanning)")

        elif total[ip] >= 100:
            print(f"[!] {ip} - {total[ip]} total requests - (possible brute force)")


df = loadCSV("MVP-Log-File-Analyzer-Project/test_logs_attack_heavy.csv")

failed_attempts, not_found_attempts, total_attempts = analyseData(df)

createReport(failed_attempts, not_found_attempts, total_attempts)


    


