from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import requests
from requests import Session
from urllib3 import disable_warnings

app = FastAPI()

# Відключити перевірку сертифікатів SSL
disable_warnings()

# Створити сеанс Requests з підтримкою SSL
session = Session()
session.verify = False

# Підключитися до Elasticsearch через HTTPS
es = Elasticsearch(
    ['https://localhost:9200'],
    basic_auth=('elastic', 'Qb+0WZ*a5JWiEdj3U6V_'),
    verify_certs=False
)

# Видалити індекс "cve"
index_name = 'cve'
es.indices.delete(index=index_name, ignore=[400, 404])

# Створити індекс "cve"
index_body = {
    'mappings': {
        'properties': {
            'description': {'type': 'text'},
            'date_published': {'type': 'date'},
            'severity': {'type': 'keyword'}
        }
    }
}
es.indices.create(index=index_name, body=index_body)

def fetch_cve_data():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cpe_description = "cpe:/o:linux:linux_kernel"
    params = {
        'cpeMatchString': cpe_description,
        'pubStartDate': (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S.000 UTC-00:00"),
        'pubEndDate': datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000 UTC-00:00")

    }
    response = requests.get(url, params=params, verify=False)
    if response.status_code == 200:
        cve_data = response.json()
        return cve_data.get('result', {}).get('CVE_Items', [])
    else:
        raise HTTPException(status_code=response.status_code, detail="Failed to fetch CVE data from NVD API")


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
    result = es.search(index=index_name, query=search_body['query'], size=search_body['size'])
    cve_list = [hit['_source'] for hit in result['hits']['hits']]
    return JSONResponse(content={"cve_list": cve_list})


@app.get("/get/new")
def get_newest_cve():
    search_body = {
        "query": {
            "match_all": {}
        },
        "size": 10,
        "sort": [
            {"date_published": {"order": "desc"}}
        ]
    }
    result = es.search(index=index_name, query=search_body['query'], size=search_body['size'], sort=search_body['sort'])
    cve_list = [hit['_source'] for hit in result['hits']['hits']]
    return JSONResponse(content={"cve_list": cve_list})


@app.get("/get/critical")
def get_critical_cve():
    search_body = {
        "query": {
            "match": {
                "severity": "critical"
            }
        },
        "size": 10,
        "sort": [
            {"date_published": {"order": "desc"}}
        ]
    }
    result = es.search(index=index_name, query=search_body['query'], size=search_body['size'], sort=search_body['sort'])
    cve_list = [hit['_source'] for hit in result['hits']['hits']]
    return JSONResponse(content={"cve_list": cve_list})


@app.get("/get")
def search_cve(query: str):
    search_body = {
        "query": {
            "match": {
                "description": query
            }
        },
        "size": 10,
        "sort": [
            {"date_published": {"order": "desc"}}
        ]
    }
    result = es.search(index=index_name, query=search_body['query'], size=search_body['size'], sort=search_body['sort'])
    cve_list = [hit['_source'] for hit in result['hits']['hits']]
    return JSONResponse(content={"cve_list": cve_list})


@app.get("/save/all")
def save_all_cve():
    cve_data = fetch_cve_data()
    for cve_item in cve_data:
        cve_doc = {
            'description': cve_item['cve']['description']['description_data'][0]['value'],
            'date_published': datetime.strptime(cve_item['publishedDate'], "%Y-%m-%dT%H:%MZ"),
            'severity': cve_item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        }
        es.index(index=index_name, body=cve_doc)
    return {"message": "CVE data saved successfully"}


@app.get("/save/new")
def save_newest_cve():
    cve_data = fetch_cve_data()
    for cve_item in cve_data[:10]:
        cve_doc = {
            'description': cve_item['cve']['description']['description_data'][0]['value'],
            'date_published': datetime.strptime(cve_item['publishedDate'], "%Y-%m-%dT%H:%MZ"),
            'severity': cve_item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        }
        res = es.index(index=index_name, body=cve_doc)
        print(res)
    return {"message": "Newest CVE data saved successfully"}


@app.get("/save/critical")
def save_critical_cve():
    cve_data = fetch_cve_data()
    critical_cve = [cve_item for cve_item in cve_data if cve_item['impact']['baseMetricV3']['cvssV3']['baseSeverity'] == "critical"]
    for cve_item in critical_cve[:10]:
        cve_doc = {
            'description': cve_item['cve']['description']['description_data'][0]['value'],
            'date_published': datetime.strptime(cve_item['publishedDate'], "%Y-%m-%dT%H:%MZ"),
            'severity': cve_item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        }
        es.index(index=index_name, body=cve_doc)
    return {"message": "Critical CVE data saved successfully"}


@app.get("/save")
def save_search_cve(query: str):
    cve_data = fetch_cve_data()
    matching_cve = [cve_item for cve_item in cve_data if query.lower() in cve_item['cve']['description']['description_data'][0]['value'].lower()]
    for cve_item in matching_cve[:10]:
        cve_doc = {
            'description': cve_item['cve']['description']['description_data'][0]['value'],
            'date_published': datetime.strptime(cve_item['publishedDate'], "%Y-%m-%dT%H:%MZ"),
            'severity': cve_item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        }
        es.index(index=index_name, body=cve_doc)
    return {"message": f"CVE data containing '{query}' saved successfully"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
