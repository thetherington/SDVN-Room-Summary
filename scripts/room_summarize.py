import copy
import datetime
import json
import urllib.parse
from threading import Thread

import requests


class summary_builder:
    def __init__(self, **kwargs):

        self.annotate = None
        self.url = None
        self.insite = None
        self.time_lookup = "15m"

        for key, value in kwargs.items():

            if key == "insite" and value:

                self.insite = value

                self.url_ipg = "http://%s:9200/%s/_search/" % (
                    self.insite,
                    urllib.parse.quote(
                        "<log-metric-p-ipg-{now/d}>,<log-metric-p-ipg-{now/d-1d}>",
                        safe="",
                    ),
                )

                self.url_magnum = "http://%s:9200/%s/_search/" % (
                    self.insite,
                    urllib.parse.quote(
                        "<log-metric-p-magnum-{now/d}>,<log-metric-p-magnum-{now/d-1d}>",
                        safe="",
                    ),
                )

            if key == "annotate" and isinstance(value, dict):

                exec("from {} import {}".format(value["module"], value["dict"]), globals())

                self.annotate = eval(value["dict"])

            if key == "annotate_db" and isinstance(value, dict):
                self.annotate = value

            if key == "time_lookup" and value:
                self.time_lookup = value

        self.ipg_link_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"from": "now-{}".format(self.time_lookup), "to": "now"}}},
                        {"match_phrase": {"event.dataset": "ipg.linkmon"}},
                        {"match_phrase": {"ipg.linkmon.s_type": "port"}},
                        {"match_phrase": {"ipg.linkmon.b_fault": "true"}},
                    ]
                }
            },
            "aggs": {
                "PCR": {
                    "terms": {"field": "ipg.linkmon.s_pcr", "size": 50, "order": {"_term": "desc"}},
                    "aggs": {
                        "DEVICE": {
                            "terms": {"field": "ipg.linkmon.s_device_name", "size": 1000, "order": {"_term": "desc"}},
                            "aggs": {
                                "LINK": {
                                    "terms": {"field": "ipg.linkmon.i_link", "size": 10, "order": {"_term": "desc"}},
                                    "aggs": {
                                        "ISSUES": {
                                            "top_hits": {
                                                "size": 1,
                                                "docvalue_fields": ["ipg.linkmon.as_fault_list"],
                                                "_source": False,
                                                "sort": [{"@timestamp": {"order": "desc"}}],
                                            }
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            },
        }

        self.ipg_status_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"from": "now-{}".format(self.time_lookup), "to": "now"}}},
                        {"match_phrase": {"event.dataset": "ipg.statusmon"}},
                        {"match_phrase": {"ipg.statusmon.s_type": "status"}},
                        {"exists": {"field": "ipg.statusmon.as_issue_list"}},
                    ]
                }
            },
            "aggs": {
                "PCR": {
                    "terms": {"field": "ipg.statusmon.s_pcr", "size": 50},
                    "aggs": {
                        "DEVICE": {
                            "terms": {"field": "ipg.statusmon.s_device_name", "size": 10, "order": {"_term": "desc"}},
                            "aggs": {
                                "ISSUES": {
                                    "top_hits": {
                                        "size": 1,
                                        "docvalue_fields": [
                                            "ipg.statusmon.i_num_issues",
                                            "ipg.statusmon.i_severity_code",
                                            "ipg.statusmon.s_status_descr",
                                            "ipg.statusmon.s_status_color",
                                        ],
                                        "_source": False,
                                        "sort": [{"@timestamp": {"order": "desc"}}],
                                    }
                                }
                            },
                        }
                    },
                }
            },
        }

        self.salvo_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"magnum.salvo.t_time": {"from": "now-0d/d", "to": "now/d"}}},
                        {"match_phrase": {"event.dataset": "magnum.salvo"}},
                    ]
                }
            },
            "aggs": {
                "ROOM": {
                    "terms": {"field": "magnum.salvo.s_pcr", "size": 100},
                    "aggs": {"RESULTS": {"terms": {"field": "magnum.salvo.s_result", "size": 10}}},
                }
            },
        }

        self.magnum_status_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"from": "now-{}".format(self.time_lookup), "to": "now"}}},
                        {"match_phrase": {"event.dataset": "magnum.service"}},
                        {"match_phrase": {"magnum.service.s_type": "overall"}},
                    ]
                }
            },
            "aggs": {
                "server": {
                    "terms": {"field": "host.name", "size": 100},
                    "aggs": {
                        "issues": {
                            "top_hits": {
                                "size": 1,
                                "docvalue_fields": ["magnum.service.i_num_failed"],
                                "_source": False,
                                "sort": [{"@timestamp": {"order": "desc"}}],
                            }
                        }
                    },
                }
            },
        }

        self.magnum_redundancy_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"from": "now-{}".format(self.time_lookup), "to": "now"}}},
                        {"match_phrase": {"event.dataset": "magnum.redundancy"}},
                    ]
                }
            },
            "aggs": {
                "room": {
                    "terms": {"field": "magnum.redundancy.s_system", "size": 100},
                    "aggs": {
                        "server": {
                            "terms": {"field": "magnum.redundancy.s_host", "size": 10, "order": {"_term": "asc"}},
                            "aggs": {
                                "description": {
                                    "top_hits": {
                                        "size": 1,
                                        "docvalue_fields": ["magnum.redundancy.s_status"],
                                        "_source": False,
                                        "sort": [{"@timestamp": {"order": "desc"}}],
                                    }
                                }
                            },
                        }
                    },
                }
            },
        }

        self.field_template = {}

        if self.annotate:

            status_component_queries = []
            link_component_queries = []

            for room, parts in self.annotate.items():

                self.field_template.update(
                    {
                        room: {
                            "as_components": ["PCR"],
                            "i_pcr_status_issues": 0,
                            "i_pcr_status_code": 0,
                            "s_pcr_status_color": 0,
                            "s_pcr_status_descr": "None",
                            "i_pcr_linkmon_issues": 0,
                            "s_pcr": room,
                            "i_pcr_salvo_success": 0,
                            "i_pcr_salvo_failed": 0,
                            "i_pcr_magnum_issues": 0,
                            "s_pcr_magnum_x_redundancy": "None",
                            "s_pcr_magnum_y_redundancy": "None",
                            "s_type": "overall",
                        }
                    }
                )

                for item, value in parts.items():

                    if not isinstance(value, list):

                        self.field_template[room].update(
                            {
                                "i_" + item.lower() + "_status_issues": 0,
                                "i_" + item.lower() + "_status_code": 0,
                                "s_" + item.lower() + "_status_color": 0,
                                "s_" + item.lower() + "_status_descr": 0,
                                "i_" + item.lower() + "_linkmon_issues": 0,
                                "s_" + item.lower(): value,
                            }
                        )

                        self.field_template[room]["as_components"].append(item)

                        _agg = copy.deepcopy(self.ipg_status_query["aggs"]["PCR"])
                        _agg["terms"]["field"] = "ipg.statusmon.s_{}".format(item.lower())
                        status_component_queries.append({item: _agg})

                        _agg = copy.deepcopy(self.ipg_link_query["aggs"]["PCR"])
                        _agg["terms"]["field"] = "ipg.linkmon.s_{}".format(item.lower())
                        link_component_queries.append({item: _agg})

            for query in status_component_queries:
                self.ipg_status_query["aggs"].update(query)

            for query in link_component_queries:
                self.ipg_link_query["aggs"].update(query)

    def fetch(self, url, query):

        try:

            header = {"Content-Type": "application/json"}
            params = {"ignore_unavailable": "true"}

            response = requests.get(url, data=json.dumps(query), headers=header, params=params, timeout=30.0)
            response.close()

            return json.loads(response.text)

        except Exception as e:

            with open("summary_builder", "a+") as f:
                f.write(str(datetime.datetime.now()) + " --- " + "fetch_method" + "\t" + str(e) + "\r\n")

            return None

    def ipg_process_statusmon(self, fields):

        results = self.fetch(self.url_ipg, self.ipg_status_query)

        try:
            # group agg query result objects (PCR, SWITCHER...)
            for group_key, agg in results["aggregations"].items():

                # terms of objects found in a group
                for bucket in agg["buckets"]:

                    # term name (PCR room name, or switcher name)
                    bucket_key = bucket["key"]

                    # IPG objects in a group
                    for edge in bucket["DEVICE"]["buckets"]:

                        # test if the issues top hits is in the edge object
                        try:

                            top_hit = edge["ISSUES"]["hits"]["hits"][-1]["fields"]

                            number_issues = top_hit["ipg.statusmon.i_num_issues"][-1]
                            severity_code = top_hit["ipg.statusmon.i_severity_code"][-1]
                            severity_color = top_hit["ipg.statusmon.s_status_color"][-1]
                            severity_descr = top_hit["ipg.statusmon.s_status_descr"][-1]

                            # scan through each of the document template to find the room
                            for _, values in fields.items():

                                if values["s_{}".format(group_key.lower())] == bucket_key:

                                    values["i_{}_status_issues".format(group_key.lower())] += number_issues

                                    # Test if the document severity code is greater then the stored
                                    # severity. if greater then update the fields with the higher severity
                                    if severity_code > values["i_{}_status_code".format(group_key.lower())]:

                                        values["i_{}_status_code".format(group_key.lower())] = severity_code
                                        values["s_{}_status_descr".format(group_key.lower())] = severity_descr
                                        values["s_{}_status_color".format(group_key.lower())] = severity_color

                        except Exception as e:
                            print(e)
                            continue

        except Exception as e:
            print(e)

        return fields

    def ipg_process_linkmon(self, fields):

        results = self.fetch(self.url_ipg, self.ipg_link_query)

        try:

            # group agg query result objects (PCR, SWITCHER...)
            for group_key, agg in results["aggregations"].items():

                # terms of objects found in a group
                for bucket in agg["buckets"]:

                    # term name (PCR room name, or switcher name)
                    bucket_key = bucket["key"]

                    # IPG objects in a group
                    for edge in bucket["DEVICE"]["buckets"]:
                        for link in edge["LINK"]["buckets"]:

                            try:

                                number_issues = len(link["ISSUES"]["hits"]["hits"][-1]["fields"]["ipg.linkmon.as_fault_list"])

                                for _, values in fields.items():

                                    if values["s_{}".format(group_key.lower())] == bucket_key:

                                        values["i_{}_linkmon_issues".format(group_key.lower())] += number_issues

                            except Exception as e:
                                print(e)
                                continue

        except Exception as e:
            print(e)

        return fields

    def process_salvo(self, fields):

        results = self.fetch(self.url_magnum, self.salvo_query)

        try:

            for room in results["aggregations"]["ROOM"]["buckets"]:

                pcr = room["key"]

                for result in room["RESULTS"]["buckets"]:

                    if pcr in fields.keys():
                        fields[pcr]["i_pcr_salvo_{}".format(result["key"])] += result["doc_count"]

        except Exception as e:
            print(e)

    def process_magnum_status(self, fields):

        results = self.fetch(self.url_magnum, self.magnum_status_query)

        try:

            for server in results["aggregations"]["server"]["buckets"]:

                magnum_name = server["key"]
                num_issues = 0

                if "issues" in server.keys():

                    for hit in server["issues"]["hits"]["hits"]:
                        num_issues += hit["fields"]["magnum.service.i_num_failed"][-1]

                for room, items in fields.items():

                    if room in magnum_name:
                        items["i_pcr_magnum_issues"] += num_issues

        except Exception as e:
            print(e)

    def process_magnum_redundancy(self, fields):

        results = self.fetch(self.url_magnum, self.magnum_redundancy_query)

        try:

            for room_collection in results["aggregations"]["room"]["buckets"]:

                for server in room_collection["server"]["buckets"]:

                    server_name = server["key"]
                    server_key = server["key"][-1:]

                    try:

                        server_desc = server["description"]["hits"]["hits"][-1]["fields"]["magnum.redundancy.s_status"][-1]

                        for room, items in fields.items():

                            if room in server_name:
                                items["s_pcr_magnum_{}_redundancy".format(server_key.lower())] = server_desc

                    except Exception as e:
                        print(e)
                        continue

        except Exception as e:
            print(e)

    def process_summary(self):

        fields = copy.deepcopy(self.field_template)

        threads = []

        func_list = [
            self.ipg_process_statusmon,
            self.ipg_process_linkmon,
            self.process_salvo,
            self.process_magnum_status,
            self.process_magnum_redundancy,
        ]

        threads.extend([Thread(target=func, args=(fields,)) for func in func_list])

        for x in threads:
            x.start()

        for y in threads:
            y.join()

        documents = []

        for _, metrics in fields.items():

            # complete the summary document
            document = {"fields": metrics, "host": self.insite, "name": "overall"}
            documents.append(document)

            for component in metrics["as_components"]:

                num_issues = 0

                num_issues += metrics["i_{}_status_issues".format(component.lower())]
                num_issues += metrics["i_{}_linkmon_issues".format(component.lower())]

                document = {
                    "fields": {
                        "label": metrics["s_{}".format(component.lower())],
                        "num_issues": num_issues,
                        "component": component,
                        "type": "component",
                    },
                    "host": self.insite,
                    "name": "component",
                }

                documents.append(document)

        return documents


def main():

    params = {
        "insite": "172.16.205.77",
        "time_lookup": "24h",
        "annotate": {"module": "ThirtyRock_PROD_edge_def", "dict": "ROOM_COLLECTION"},
    }

    summary = summary_builder(**params)

    print(json.dumps(summary.process_summary(), indent=2))


if __name__ == "__main__":
    main()
