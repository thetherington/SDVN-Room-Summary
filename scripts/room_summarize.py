import copy
import datetime
import json
from threading import Thread

import requests


class summary_builder:
    def __init__(self, **kwargs):

        self.annotate = None
        self.url = None
        self.insite = None

        for key, value in kwargs.items():

            if key == "insite" and value:
                self.insite = value
                self.url = "http://{}:9200/log-metric-poller-ipg-*/_search".format(value)

            if key == "annotate" and isinstance(value, dict):

                exec("from {} import {}".format(value["module"], value["dict"]), globals())

                self.annotate = eval(value["dict"])

            if key == "annotate_db" and isinstance(value, dict):
                self.annotate = value

        self.ipg_link_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"match_phrase": {"poller.ipg.linkmon.b_fault": {"query": True}}},
                        {"range": {"@timestamp": {"from": "now-1m", "to": "now"}}},
                    ]
                }
            },
            "aggs": {
                "PCR": {
                    "terms": {
                        "field": "poller.ipg.linkmon.s_pcr",
                        "size": 50,
                        "order": {"_term": "desc"},
                    },
                    "aggs": {
                        "DEVICE": {
                            "terms": {
                                "field": "poller.ipg.linkmon.s_device_name",
                                "size": 1000,
                                "order": {"_term": "desc"},
                            },
                            "aggs": {
                                "LINK": {
                                    "terms": {
                                        "field": "poller.ipg.linkmon.i_link",
                                        "size": 10,
                                        "order": {"_term": "desc"},
                                    },
                                    "aggs": {
                                        "ISSUES": {
                                            "top_hits": {
                                                "docvalue_fields": [
                                                    "poller.ipg.linkmon.as_fault_list",
                                                ],
                                                "_source": "poller.ipg.statusmon.i_num_issues",
                                                "size": 1,
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
                        {"exists": {"field": "poller.ipg.statusmon.s_issues"}},
                        {"range": {"@timestamp": {"from": "now-7m", "to": "now"}}},
                    ]
                }
            },
            "aggs": {
                "PCR": {
                    "terms": {
                        "field": "poller.ipg.statusmon.s_pcr",
                        "size": 50,
                        "order": {"_term": "desc"},
                    },
                    "aggs": {
                        "DEVICE": {
                            "terms": {
                                "field": "poller.ipg.statusmon.s_device_name",
                                "size": 1000,
                                "order": {"_term": "desc"},
                            },
                            "aggs": {
                                "ISSUES": {
                                    "top_hits": {
                                        "docvalue_fields": [
                                            "poller.ipg.statusmon.i_num_issues",
                                            "poller.ipg.statusmon.i_severity_code",
                                            "poller.ipg.statusmon.s_status_descr",
                                            "poller.ipg.statusmon.s_status_color",
                                        ],
                                        "size": 1,
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
            "query": {"range": {"poller.salvo.salvo_mon.t_time": {"from": "now-0d/d", "to": "now/d"}}},
            "aggs": {
                "ROOM": {
                    "terms": {"field": "poller.salvo.salvo_mon.s_pcr", "size": 100},
                    "aggs": {"RESULTS": {"terms": {"field": "poller.salvo.salvo_mon.s_result", "size": 10}}},
                }
            },
        }

        self.magnum_status_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"from": "now-5m", "to": "now"}}},
                        {"match_phrase": {"poller.magnum.api.s_type": {"query": "summary"}}},
                    ]
                }
            },
            "aggs": {
                "server": {
                    "terms": {"field": "host", "size": 50},
                    "aggs": {
                        "issues": {
                            "top_hits": {
                                "size": 1,
                                "docvalue_fields": ["poller.magnum.api.i_issues"],
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
                        {"range": {"@timestamp": {"from": "now-5m", "to": "now"}}},
                        {"match_phrase": {"poller.magnum.api.s_type": {"query": "redundancy_mon"}}},
                    ]
                }
            },
            "aggs": {
                "room": {
                    "terms": {"field": "host", "size": 100},
                    "aggs": {
                        "server": {
                            "terms": {
                                "field": "poller.magnum.api.s_server",
                                "size": 10,
                                "order": {"_term": "asc"},
                            },
                            "aggs": {
                                "description": {
                                    "top_hits": {
                                        "docvalue_fields": ["poller.magnum.api.s_state_descr"],
                                        "size": 1,
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
                        _agg["terms"]["field"] = "poller.ipg.statusmon.s_{}".format(item.lower())
                        status_component_queries.append({item: _agg})

                        _agg = copy.deepcopy(self.ipg_link_query["aggs"]["PCR"])
                        _agg["terms"]["field"] = "poller.ipg.linkmon.s_{}".format(item.lower())
                        link_component_queries.append({item: _agg})

            for query in status_component_queries:
                self.ipg_status_query["aggs"].update(query)

            for query in link_component_queries:
                self.ipg_link_query["aggs"].update(query)

    def fetch(self, url, query):

        try:

            response = requests.get(url, data=json.dumps(query), timeout=30.0)

            return json.loads(response.text)

        except Exception as e:

            with open("summary_builder", "a+") as f:
                f.write(str(datetime.datetime.now()) + " --- " + "magnum_cache_builder" + "\t" + str(e) + "\r\n")

            return None

    def ipg_process_statusmon(self, fields):

        results = self.fetch(self.url, self.ipg_status_query)

        if isinstance(results, dict):
            if "aggregations" in results.keys():

                # group agg query result objects (PCR, SWITCHER...)
                for group_key, agg in results["aggregations"].items():

                    # terms of objects found in a group
                    for bucket in agg["buckets"]:

                        # term name (PCR room name, or switcher name)
                        bucket_key = bucket["key"]

                        # IPG objects in a group
                        for edge in bucket["DEVICE"]["buckets"]:

                            # IPG name
                            edge_key = edge["key"]

                            # test if the issues top hits is in the edge object
                            if "ISSUES" in edge.keys():

                                number_issues = edge["ISSUES"]["hits"]["hits"][-1]["fields"]["poller.ipg.statusmon.i_num_issues"][
                                    -1
                                ]

                                severity_code = edge["ISSUES"]["hits"]["hits"][-1]["fields"][
                                    "poller.ipg.statusmon.i_severity_code"
                                ][-1]

                                severity_color = edge["ISSUES"]["hits"]["hits"][-1]["fields"][
                                    "poller.ipg.statusmon.s_status_color"
                                ][-1]

                                severity_descr = edge["ISSUES"]["hits"]["hits"][-1]["fields"][
                                    "poller.ipg.statusmon.s_status_descr"
                                ][-1]

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

        return fields

    def ipg_process_linkmon(self, fields):

        results = self.fetch(self.url, self.ipg_link_query)

        if isinstance(results, dict):
            if "aggregations" in results.keys():

                # group agg query result objects (PCR, SWITCHER...)
                for group_key, agg in results["aggregations"].items():

                    # terms of objects found in a group
                    for bucket in agg["buckets"]:

                        # term name (PCR room name, or switcher name)
                        bucket_key = bucket["key"]

                        # IPG objects in a group
                        for edge in bucket["DEVICE"]["buckets"]:

                            # IPG name
                            edge_key = edge["key"]

                            for link in edge["LINK"]["buckets"]:

                                if "ISSUES" in link.keys():

                                    number_issues = len(
                                        link["ISSUES"]["hits"]["hits"][-1]["fields"]["poller.ipg.linkmon.as_fault_list"]
                                    )

                                    for _, values in fields.items():

                                        if values["s_{}".format(group_key.lower())] == bucket_key:

                                            values["i_{}_linkmon_issues".format(group_key.lower())] += number_issues

        return fields

    def process_salvo(self, fields):

        results = self.fetch("http://{}:9200/log-metric-poller-salvo-*/_search".format(self.insite), self.salvo_query)

        if isinstance(results, dict):
            if "aggregations" in results.keys():

                for room in results["aggregations"]["ROOM"]["buckets"]:

                    pcr = room["key"]

                    for result in room["RESULTS"]["buckets"]:

                        if pcr in fields.keys():
                            fields[pcr]["i_pcr_salvo_{}".format(result["key"])] += result["doc_count"]

    def process_magnum_status(self, fields):

        results = self.fetch(
            "http://{}:9200/log-metric-poller-magnum-*/_search".format(self.insite),
            self.magnum_status_query,
        )

        if isinstance(results, dict):
            if "aggregations" in results.keys():

                for server in results["aggregations"]["server"]["buckets"]:

                    magnum_name = server["key"]
                    num_issues = 0

                    if "issues" in server.keys():

                        for hit in server["issues"]["hits"]["hits"]:
                            num_issues += hit["fields"]["poller.magnum.api.i_issues"][-1]

                    for room, items in fields.items():

                        if room in magnum_name:
                            items["i_pcr_magnum_issues"] += num_issues

    def process_magnum_redundancy(self, fields):

        results = self.fetch(
            "http://{}:9200/log-metric-poller-magnum-*/_search".format(self.insite),
            self.magnum_redundancy_query,
        )

        if isinstance(results, dict):
            if "aggregations" in results.keys():

                for room in results["aggregations"]["room"]["buckets"]:

                    room_name = room["key"]

                    if "server" in room.keys():
                        for server in room["server"]["buckets"]:

                            server_name = server["key"]
                            server_key = server["key"][-1:]

                            if "description" in server.keys():
                                for hit in server["description"]["hits"]["hits"]:
                                    server_desc = hit["fields"]["poller.magnum.api.s_state_descr"][-1]

                            for room, items in fields.items():

                                if room in server_name:
                                    items["s_pcr_magnum_{}_redundancy".format(server_key.lower())] = server_desc

    def process_summary(self):

        fields = copy.deepcopy(self.field_template)

        threads = []

        threads.append(Thread(target=self.ipg_process_statusmon, args=(fields,)))
        threads.append(Thread(target=self.ipg_process_linkmon, args=(fields,)))
        threads.append(Thread(target=self.process_salvo, args=(fields,)))
        threads.append(Thread(target=self.process_magnum_status, args=(fields,)))
        threads.append(Thread(target=self.process_magnum_redundancy, args=(fields,)))

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
        "insite": "172.16.205.201",
        "annotate": {"module": "ThirtyRock_PROD_edge_def", "dict": "ROOM_COLLECTION"},
    }

    summary = summary_builder(**params)

    print(json.dumps(summary.process_summary(), indent=2))

    summary.process_magnum_redundancy({})


if __name__ == "__main__":
    main()
