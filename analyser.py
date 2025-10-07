import pandas as pd    
from collections import defaultdict

def loadCSV(filename): #Opens the test csv and loads it into a DataFrame
    
    df = pd.read_csv(filename)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="%d/%b/%Y:%H:%M:%S", errors="coerce") #turns the timestamp column into a datetime object
    df = df.dropna(subset=["timestamp"]) #drops rows that cant be parsed
    df["status"] = df["status"].astype(int) #converts the status column into ints
    
    df.set_index("timestamp", inplace=True) #sets the index as the timestamp to measure time between requests

    return df

def analyseData(df):

    alerts = []

    for ip, group in df.groupby("ip"): #groups the datafram on ip addresses
        
        per_minute = group.resample("1Min") #resamples the data for each ip address into 1 minute intervals

        counts = per_minute["status"].value_counts().unstack(fill_value=0) #counts the occurences of each code per minute assigning a 0 to minutes that no code occured

       

        for time, row in counts.iterrows():
                
            total_requests = row.sum()
            failed_logins = row.get(401, 0) + row.get(403, 0)
            not_found = row.get(404, 0)

                # Apply thresholds
            if failed_logins > 5:
                alerts.append(f"[!] {ip} - {failed_logins} failed logins at {time} (possible brute force)")

            if not_found > 10:
                alerts.append(f"[!] {ip} - {not_found} 404 errors at {time} (possible scanning)")

            if total_requests > 100:
                alerts.append(f"[!] {ip} - {total_requests} requests at {time} (possible DoS/scraping)")

    return alerts

def createReport(alerts):

    print("=== SUSPICIOUS ACTIVITY ===")

    if not alerts:
        print("No suspicious activity detected")
    else:
        for alert in alerts:
            print(alert)


df = loadCSV("MVP-Log-File-Analyzer-Project/test_logs.csv")

alerts = analyseData(df)

createReport(alerts)


    


