# **Artifactory AQL Scanner (Shai-Hulud 2.0)**

This tool is a shell script designed to scan a JFrog Artifactory instance for malicious packages associated with the **Shai-Hulud 2.0** supply chain attack.

It automatically fetches the latest Indicators of Compromise (IOCs) from JFrog Research, constructs the expected filenames for the malicious artifacts (handling npm scopes and versioning), and uses **Artifactory Query Language (AQL)** to identify if any of these files exist in your repositories.

## **Features**

* **Automated Intel Feed:** Fetches the latest IOC CSV directly from research.jfrog.com.  
* **AQL Integration:** Uses the performant items.find AQL query to search across all repositories.  
* **Reporting:** Generates a CSV report (aql\_scan\_report.csv) listing found artifacts with their repository location and path.

## **Prerequisites**

* **Bash**: Standard shell environment (Linux/macOS/WSL).  
* **cURL**: For making network requests.  
* **jq**: Required for parsing JSON responses from the Artifactory API.

### **Installation**

1. Clone this repository:  
```sh
   git clone https://github.com/jaganse/rt-npm-file-scanner.git 
   cd rt-npm-file-scanner
```
2. Ensure the script is executable:  
```sh
   chmod +x rt-aql-scanner.sh
```


## **Usage**

1. Export your Artifactory API Token:  
   You must provide your Bearer token via an environment variable `rt_token`.  
```   
   export rt_token="your\_actual\_bearer\_token\_here"
```
2. **Run the Scanner:**  
```
   ./rt-aql-scanner.sh https://your-artifactory-url.com
```
## **How It Works**

1. **Fetch:** Downloads the IOC CSV from JFrog Research.  
3. **Filename Construction:**  
   * The script converts npm package names to Artifactory storage filenames.  
   * **Scoped Packages:** If a package is named @accordproject/concerto-analysis, the script strips the scope to search for the actual filename concerto-analysis-3.24.1.tgz.  
   * **Standard Packages:** 02-echo becomes 02-echo-0.0.7.tgz.  
4. **Search:** It sends a POST request to /artifactory/api/search/aql with the query:  
   items.find({"name":{"$eq":"calculated-filename.tgz"}})

## **Output**

The script generates two files upon completion:

### **1\. found\_artifacts.csv (Action Required)**

Contains **only** the malicious artifacts successfully found in your Artifactory instance. If this file is not empty, immediate action is required.


### **2\. full\_scan\_log.csv (Audit Trail)**

A complete log of every single package/version pair checked against Artifactory, including those that were NOT\_FOUND. Use this for audit purposes to prove the scan covered all targets.

<!-- ## **License**

[MIT](https://www.google.com/search?q=LICENSE) -->
