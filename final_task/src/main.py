from fastapi import FastAPI, HTTPException
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import requests

app = FastAPI()
es = Elasticsearch(['http://localhost:9200'])

@app.get("/info")
def get_app_info():
    app_info = {
        "author": "Iryna Berezinska",
        "description": "Your Application Description"
    }
    return app_info

@app.get("/get/all")
def get_all_cve():
    search_body = {
        "query": {
            "match_all": {}
        },
        "size": 40
    }
    result = es.search(index='cve', body=search_body)
    cve_list = [hit['_source'] for hit in result['hits']['hits']]
    return cve_list

@app.get("/get/new")
def get_newest_cve():
    five_days_ago = datetime.now() - timedelta(days=5)
    search_body = {
        "query": {
            "range": {
                "date_published": {
                    "gte": five_days_ago.strftime("%Y-%m-%d")
                }
            }
        },
        "size": 10,
        "sort": [
            {"date_published": {"order": "desc"}}
        ]
    }
    result = es.search(index='cve', body=search_body)
    cve_list = [hit['_source'] for hit in result['hits']['hits']]
    return cve_list

@app.get("/get/critical")
def get_critical_cve():
    search_body = {
        "query": {
            "term": {
                "severity": "critical"
            }
        },
        "size": 10
    }
    result = es.search(index='cve', body=search_body)
    cve_list = [hit['_source'] for hit in result['hits']['hits']]
    return cve_list

@app.get("/get")
def search_cve(query: str):
    search_body = {
        "query": {
            "match": {
                "description": query
            }
        },
        "size": 10
    }
    result = es.search(index='cve', body=search_body)
    cve_list = [hit['_source'] for hit in result['hits']['hits']]
    return cve_list

@app.get("/cve")
def get_cve():
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    cpe_description = "cpe:/o:linux:linux_kernel"
    response = requests.get(url, params={"cpeMatchString": cpe_description})
    if response.status_code == 200:
        cve_data = response.json()
        return cve_data
    else:
        raise HTTPException(status_code=response.status_code, detail="Failed to fetch CVE data")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
