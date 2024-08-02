#!/usr/bin/env python3

"""
######################################################################
# Empresa: Sercompe
# Autor: Luis G. Fernandes
# Email: luis.fernandes@sercompe.com.br
# Funcao: Obter dados do FortiGate via API
# Zabbix Version: 4.2
# Create date: 13/02/2024
# History Updates: 
# 13/02/2024 - Função policy_syslog
# 21/06/2024 - Adicionado classes e as funções: perf_sla, interfaces_bandwidth e interfaces_config
######################################################################
"""

import requests
import json
import sys
import os
import pwd
from inspect import currentframe
from datetime import datetime

# Desabilitando o alerta que informa que o certificado não é valido
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class Log:
    def print_error(self, line, error):
        print(f'Linha: {line} - Erro: {error}.')
    
    def print_json(self, json_data):
        print(json.dumps(json_data, indent=2))
       
class Connection:
    def ping_verify(self, endereco):
        result = os.popen("ping -c 1 " + endereco).read()
        if "ttl=" not in result:
            Log().print_error(sys._getframe().f_lineno,'Device nao encontrado na rede utilizando ICMP Ping')
            exit()
        else:
            return True
    
    def api_path(self, method,key,parameter=0):
        list = {
                "policyConfig": f"/api/v2/cmdb/firewall/policy?access_token={key}&format=policyid|name",
                "policyIprope": f"/api/v2/monitor/firewall/policy?access_token={key}&format=policyid|bytes",
                "list_vdoms": f"/api/v2/monitor/web-ui/state?access_token={key}",
                "perf_sla": f"/api/v2/monitor/virtual-wan/health-check?access_token={key}&vdom={parameter}",
                "interfaces_bandwidth": f"/api/v2/monitor/virtual-wan/members?access_token={key}&vdom={parameter}",
                "interfaces_config": f"/api/v2/monitor/system/available-interfaces?access_token={key}&vdom={parameter}"
            }
        
        if method in list:
            return list[method]
        else:
            Log().print_error(sys._getframe().f_lineno,'Falha em identificar o path para requisitar na API')
            exit(0)

    def api_request(self, path):
        try:
            headers = {'accept': 'application/json'}
            response = requests.get(f'{_API_PATH}{path}',headers=headers,verify=False,timeout=10)
            result = json.loads(response.text)
            if response != None and response.status_code == 200:
                return result
            else:
                Log().print_error(sys._getframe().f_lineno,f'Retorno da API com erro:\n{response.text}')
                exit(0)
        except Exception as err:
            Log().print_error(sys._getframe().f_lineno,'Erro na coleta dos dados')
            exit(0)

class Filter:
    def policy_syslog(self, iprope, config):
        try:
            result = iprope["results"]
            a = {}
            for i in result:
                a[i["policyid"]] = i["bytes"]
        except Exception as err:
            Log().print_error(sys._getframe().f_lineno,f'Erro na conversão dos dados iprope de list para dict\nErro: {err}')
            exit(0)
        try:
            result = config["results"]
            policy = []
            for i in result:
                if i["name"].startswith("SYSLOG "):
                    if i["policyid"] in a.keys():
                        i['bytes'] = a[i["policyid"]]
                    else:
                        i['bytes'] = 0
                    policy.append(i)
        except Exception as err:
            Log().print_error(sys._getframe().f_lineno,f'Erro na criação de um dict com a policy name e os bytes\nErro: {err}')
            exit(0)
        return policy

    def filter(self, type, data):
        if type == "perf_sla":
            result = []
            for entry in data['results']:
                for e in data['results'][entry]:
                    if data['results'][entry][e]['status'] == 'up':
                        result += [{
                            'vdom': data['vdom'],
                            'name': str(entry),
                            'participant': e,
                            'status': data['results'][entry][e]['status'],
                            'packet_loss': data['results'][entry][e]['packet_loss'],
                            'latency': data['results'][entry][e]['latency'],
                            'jitter': data['results'][entry][e]['jitter'],
                        }]
                    elif data['results'][entry][e]['status'] == 'down':
                        result += [{
                            'vdom': data['vdom'],
                            'name': str(entry),
                            'participant': e,
                            'status': 'down',
                            'packet_loss': 100.0,
                            'latency': 100.0,
                            'jitter': 100.0,
                        }]
        elif type == "interfaces_bandwidth":
            result = []
            for entry in data['results']:
                if data['results'][entry]['link'] == 'up':
                    result += [{
                        'vdom': data['vdom'],
                        'name': str(entry),
                        'link': data['results'][entry]['link'],
                        'tx_bandwidth': data['results'][entry]['tx_bandwidth'],
                        'rx_bandwidth': data['results'][entry]['rx_bandwidth']
                    }]
                else:
                    result += [{
                        'vdom': data['vdom'],
                        'name': str(entry),
                        'link': 'down',
                        'tx_bandwidth': 0,
                        'rx_bandwidth': 0
                    }]
        elif type == "interfaces_config":
            result = []
            for entry in data['results']:
                if 'role' in entry:
                    if entry['role'] == 'wan':
                        estimated_upstream_bandwidth = entry['estimated_upstream_bandwidth']
                        estimated_downstream_bandwidth = entry['estimated_downstream_bandwidth']
                    else:
                        estimated_upstream_bandwidth = 0
                        estimated_downstream_bandwidth = 0
                    
                    if 'tunnel_interface' in entry:
                        tunnel_interface = entry['tunnel_interface']
                    else:
                        tunnel_interface = 'None'
                    
                    result += [{
                        'vdom': data['vdom'],
                        'name': entry['name'],
                        'status': entry['status'],
                        'type': entry['type'],
                        'estimated_upstream_bandwidth': estimated_upstream_bandwidth,
                        'estimated_downstream_bandwidth': estimated_downstream_bandwidth,
                        'tunnel_interface': tunnel_interface
                    }]
            return result
        else:
            result = data
        return result

class Request:
    def policy_syslog(self,token):
        path = conn.api_path("policyIprope",token)
        policyIprope = conn.api_request(path)
        path = conn.api_path("policyConfig",token)
        policyConfig = conn.api_request(path)
        result = Filter().policy_syslog(policyIprope,policyConfig)
        return result
    
    def request_all_vdoms(self, token, object):
        result = []
        path = conn.api_path("list_vdoms",token)
        json_vdoms_raw = conn.api_request(path)
        vdoms = json_vdoms_raw['results']['admin']['vdoms']
        for vdom in vdoms:
            if vdom != "":
                path = conn.api_path(object,token,vdom)
                data = conn.api_request(path)
                result += Filter().filter(object, data)
        return result

    def only_request(self, token, object):
        path = conn.api_path(object,token)
        data = conn.api_request(path)
        result = Filter().filter(object, data)
        return result

try:
    _COMMAND = sys.argv[1]
    _HOST = sys.argv[2]
    _PORT = sys.argv[3]
    _KEY = sys.argv[4]
    if len(sys.argv) > 5:
        _PARAMS = sys.argv[5]
    _API_PATH = f"https://{_HOST}:{_PORT}"
except Exception as err:
    Log().print_error(sys._getframe().f_lineno,f'Alguma variavel nao foi informada')
    exit(0)

conn = Connection()
conn.ping_verify(_HOST)
if _COMMAND == "policy_syslog":
    result = Request().policy_syslog(_KEY)
elif _COMMAND in {"perf_sla","interfaces_bandwidth","interfaces_config"}:
    result = Request().request_all_vdoms(_KEY,_COMMAND)
else:
    Log().print_error(sys._getframe().f_lineno,'Comando invalido')
Log().print_json(result)

