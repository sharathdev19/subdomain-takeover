from prance import  ResolvingParser
import json
import requests
import urllib
import subprocess
import string

parser = ResolvingParser('api.yml')

base_path = "https://stageapi.kreditbee.in"

pranse_obj = parser.specification['paths']

def init():
     url = "https://securetoken.googleapis.com/v1/token?key=AIzaSyDO5qd5NAp-rIXb7VMIHwA8dRaijYZRNiU"
     headers = {
     "Host": "securetoken.googleapis.com",
     "Content-Type": "application/x-www-form-urlencoded",
     "X-Client-Version":"Firefox/JsCore/5.8.6/FirebaseCore-web",
     "Origin": "https://www.kreditbee.in",
     "Referer": "https://www.kreditbee.in/eligibility/congratz"
     }
     body = {
        "grant_type":"refresh_token",
        "refresh_token":"AE0u-NcKIo3G8QKsRWpgvxWa_4Q5F7ixFLgiwpqKMN4ziFR9cMJHkPz_NA-9FgO2Z_TibxgsTyg6mS99-5XStnwa9dSjPVQND6JohmF9r6-OGEGgb5WqeA27f-KZW9ubhje_Yas3uNuNrsG_GynofaDe65CDl5iDe_ZCNX2x6BKHyQwuLEewrX4"
     }
     req = requests.post(url,headers = headers, data = body)
     json_response = req.json()

     return((json_response["access_token"]))

auth_token = "Bearer " +  init()

headers ={"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0",
            "Accept":"application/json, text/plain, */*",
            "Authorization": auth_token,
            "Accept-Encoding":"gzip, deflate",
            "Content-Type": "application/json"
            }


def getQueryParams(path,method):
    query_params = {}
    query_obj = parser.specification['paths']
    if query_obj.get(path,False) != False:
        param_obj = query_obj[path][method].get('parameters')
        if param_obj != None:
            for keys in param_obj:
                if keys['in'] == "query":
                    query_params[keys['name']] = keys['schema'].get('example',"")
                    #print(keys['name'],keys['schema'].get('example',""))
            return query_params
    else:
        return False


def getBodyParams(path,method):
    body_params = []
    body_obj = parser.specification['paths']
    #checks if the given path is present
    if body_obj.get(path,False) != False:

        if method == "POST":
            post_body = {}
            request_body = body_obj[path][method.lower()]
            # CHECKS IF THERE IS REQUEST BODY ELSE RETURN EMPTY
            if request_body.get('requestBody',False) != False:
                #AS OF NOW ONLY EXTRACTS application/json
                if request_body['requestBody']['content'].get('application/json',False) != False:
                    properties = request_body['requestBody']['content']['application/json']['schema']['properties']

                    for props in properties:

                        #IF THE BODY CONTAINS EXAMPLES
                        post_body[props] = properties[props].get('example'," ")

                    return post_body

                else:
                    #print(request_body['requestBody']['content']['application/x-www-form-urlencoded']['schema']['properties'])
                    pass
            else:
                 return False
        if method == "PUT":
            pass
        if method == "DELETE":
            pass

    else:
        return False

def getEnumValues(param):
    enums = []
    param_obj = pranse_obj['parameters']
    for params in param_obj:
        presentIn = params['in']
        if params['name'] == param:
            en = params['schema'].get('enum')
            if en is not None:
                enums  = en
    return enums

def getHTTPMethod(path):
    methods = []
    method_obj = pranse_obj[path]
    base_methods = ['post','get','put','delete']
    for method in base_methods:
        if method_obj.get(method,False) != False:
            methods.append(method)
    return methods

def print_result(path,method,result,test_case,resp = None, response = None):
        if result == "PASS":
            print(f"Path : {path:40} |\t Test Case: {test_case:35} |\t Result: Pass")
        if result == "FAIL":
            if resp:
                print(f"Path : {path:40} |\t Test Case: {test_case:35} |\t Result: Fail")
                if method == "GET":
                    print("code:", resp[0], "method:", method + "content","url", resp[1])
                    #pass
                else:
                    print("code:", resp[0], "method:", method + "content","body",resp[1])
                    #pass
            if response:
                print(f"Path : {path:40} |\t Test Case: {test_case:35} |\t Result: Fail")
                #print("code:","method:",method , response)




def bodyExist(path,method):
    obj =  pranse_obj[path][method]['requestBody']['content']['application/json']['schema']
    if obj.get('type') == 'object':
        cdict = {}
        print(obj['properties'])


def queryExist(path,method):
    return pranse_obj[path][method].get('parameters',False)


def fuzzing(path,method,query=None,body=None):
    filename = "fuzz_payloads.txt"
    file = open(filename,'r')
    if method == "GET":
        flag_checkin = []
        test_case = "Fuzzing in Query Param"
        for payloads in file :
            payloads = payloads.strip()
            query_payload = fuzz_all(query)
            query_convert_str = str(query_payload)
            query_convert_str = query_convert_str.replace("$",payloads)
            final_query = eval(query_convert_str)
            resp = requests.get(base_path + path , headers = headers, params = query)
            if resp.status_code != 200:
                flag_checkin.append(resp.status_code)
                flag_checkin.append(resp.content)

        if len(flag_checkin) > 0:
            print_result(path, method, "FAIL", test_case, resp)
        else:
            print_result(path, method, "PASS", test_case)
    if method == "POST":
        qb_flag_checkin = []
        b_flag_checkin = []
        test_case = "Fuzzing in Body Param"
        if (query) and (body):
            for payloads in file :
                payloads = payloads.strip()
                body_payload = fuzz_all(body)
                body_convert_str = str(body_payload)
                body_convert_str = body_convert_str.replace("$",payloads)
                final_body = eval(body_convert_str)
                resp = requests.post(base_path + path ,headers = headers, params = query,json = final_body)
                if resp.status_code != 200:
                    qb_flag_checkin.append(resp.status_code)
                    qb_flag_checkin.append(resp.content)

            if len(qb_flag_checkin) > 0:
                print_result(path, method,"FAIL", test_case, qb_flag_checkin)
            else:
                print_result(path,method,"PASS",test_case)
            #print("query: ",query)
            #print("body: ",body)

        if (not query) and (body):
            for payloads in file :
                payloads = payloads.strip()
                body_payload = fuzz_all(body)
                body_convert_str = str(body_payload)
                body_convert_str = body_convert_str.replace("$",payloads)
                final_body = eval(body_convert_str)
                resp = requests.post(base_path + path ,headers = headers,json = final_body)
                if resp.status_code != 200:
                    b_flag_checkin.append(resp.status_code)
                    b_flag_checkin.append(resp.content)

            if len(b_flag_checkin) > 0:
                print_result(path,method,"FAIL",test_case, b_flag_checkin)

            else:
                print_result(path,method,"PASS",test_case)

    if method == "DELETE":
        pass


def fuzz_all(params):
    refined_param = params.copy()
    for x,y in params.items():
        payload_value = "$"
        refined_param.update({x:payload_value})
    return refined_param


def dictToStr(param):
    return (urllib.parse.urlencode(param))


def get_dis_allowed_methods(methods):
    global_methods = ["POST","GET","PUT","DELETE","PATCH"]
    allowed_methods = methods
    for x in global_methods:
        if x in allowed_methods:
            global_methods.remove(x)
    return global_methods



def injection(path,method,query = None, body = None):
    if method == "GET":
        test_case = "Injection test in Request Query"
        param =  dictToStr(query)
        param = "?" + param
        get_query_path = base_path + path + param
        cmnd_get = f"sqlmap -u \'{get_query_path}\' --method  GET  -H \'Authorization: {auth_token}\'  --batch -v 0 -o | egrep \"^\[\S*\] (\[CRITICAL\][^.]+)\""

        get_proc = subprocess.Popen(cmnd_get,stdout=subprocess.PIPE,shell=True)
        get_op = get_proc.stdout.read()
        not_vul_string = "all tested parameters do not appear to be injectable."
        if not_vul_string in str(get_op):
                print_result(path,method,"PASS",test_case)
        else:
                print_result(path,method,"FAIL",test_case,response = get_op)

    else:
        test_case = "Injection test on Request Body"
        if (query) and (body):
            param = dictToStr(query)
            param = "?" + param
            get_query_path = base_path + path + param
            cmnd_query_post = f"sqlmap -u \'{get_query_path}\' --method  {method} -H \'Authorization: {auth_token}\'  --data \"{body}\" --batch -v 0 -o | egrep \"^\[\S*\] (\[CRITICAL\][^.]+)\" "

            get_proc = subprocess.Popen(cmnd_query_post,stdout=subprocess.PIPE,shell=True)
            get_op = get_proc.stdout.read()
            not_vul_string = "all tested parameters do not appear to be injectable."
            if not_vul_string in str(get_op):
                    print_result(path,method,"PASS",test_case)
            else:
                    print_result(path,method,"FAIL",test_case,response = get_op)
        if(not query) and (body):
            cmnd_post = f"sqlmap -u \'{base_path + path}\' --method  {method} -H \'Authorization: {auth_token}\'  --data \"{body}\" --batch -v 0 -o | egrep \"^\[\S*\] (\[CRITICAL\][^.]+)\" "

            get_proc = subprocess.Popen(cmnd_post,stdout=subprocess.PIPE,shell=True)
            get_op = get_proc.stdout.read()
            not_vul_string = "all tested parameters do not appear to be injectable."
            if not_vul_string in str(get_op):
                    print_result(path,method,"PASS",test_case)
            else:
                    print_result(path,method,"FAIL",test_case,response = get_op)


def content_type_modification(path,method,query = None, body = None):
    check_in = []
    test_header = headers.copy()
    test_case = "Content Type Modification"
    content_types = ['text/html','multipart/form-data','application/x-www-form-urlencoded','application/xml','image/jpeg','image/gif']
    if method == "GET":
        for ct in content_types:
            cont_header = {"Content-Type":ct}
            test_header.update(cont_header)

            req = requests.get(base_path + path, params = query, headers = test_header)
            if req.status_code != 200:
                check_in.append(req.status_code)
                check_in.append(req.content)
    else:
        if (query) and (body):
            for ct in content_types:
                cont_header = {"Content-Type":ct}
                test_header.update(cont_header)

                req = requests.request(method = method, url = base_path + path , params = query, headers = test_header, json = body)
                if req.status_code != 200:
                    check_in.append(req.status_code)
                    check_in.append(req.content)

        if(not query) and (body):
            for ct in content_types:
                cont_header = {"Content-Type":ct}
                test_header.update(cont_header)

                req = requests.request(method = method, url = base_path + path , headers = test_header, json = body)
                if req.status_code != 200:
                    check_in.append(req.status_code)
                    check_in.append(req.content)

    if len(check_in) > 0:
        print_result(path, method, "FAIL", test_case, resp = check_in)
    else:
        print_result(path, method, "PASS", test_case)


def http_method_modification(path, methods_not_allowed, query_params = None, body = None):
    test_case = "HTTP Method Modification"
    failed_tests = []
    for methods in methods_not_allowed:
        req = requests.request(method = methods, url = base_path + path, headers = headers, params = query_params, json = body)
        if req.status_code == 200:
            failed_tests.append(req.status_code)
            failed_tests.append(req.content)

    if len(failed_tests) > 0:
        print_result(path, method, "FAIL", test_case, resp = failed_tests)
    else:
        print_result(path, method, "PASS", test_case)


def ip_insuficient_params(path, method, fixed_args_num, test_in, query_params = None, body_params = None ):
    get_test_case = "Insufficient Params in Query"
    post_test_case = "Insufficient params in Body"
    query = query_params
    body = body_params

    if query_params:
        query = query_params.copy()
    if body_params:
        body = body_params.copy()


    if test_in == "QUERY":
        for i in range(fixed_args_num):
            query.popitem()
            req = requests.request(method =method,url = base_path+path, headers = headers , params = query, json = body)
            print(f"Path: {path:20} |\t Test Case : {get_test_case}, Expected: {fixed_args_num} Tested: {len(query):25}  | {req.content} ")
            print()
    if test_in == "BODY":
        for i in range(fixed_args_num):
            body.popitem()
            req = requests.request(method =method, url = base_path+path, headers = headers ,params = query, json = body)
            print(f"Path: {path:20} |\t Test Case : {post_test_case}, Expected: {fixed_args_num} Tested: {len(body):25}  | {req.content} ")
            print()

def iv_param_overflow(path, method, overflow_in, overflow_param, query_params = None, body_params = None):
    get_test_case = "Query Parameter overflow "
    post_test_case = "Body Parameter overflow "
    payloads = {'50':"50 random characters", '100' : "100 random characters",  "200" : "200 random characters"}


    if overflow_in == "QUERY":
        for k in payloads:
            size = k
            query = query_params.copy()
            test_param = {overflow_param: string_generator(int(size))}
            query.update(test_param)
            resp = requests.request(url = base_path + path, method = method,params = query, headers = headers, json = body_params)

            if resp.status_code == 200:
                print(f"Path : {path:20} |\t Test Case : {get_test_case} Testing payload size with {payloads[k]:25} |\t Result :Pass")
            else:
                print(f"Path : {path:20} |\t Test Case : {get_test_case} Testing payload size with {payloads[k]:25} |\t Result :Fail")

    if overflow_in == "BODY":
        for m in payloads:
            size = m
            body = body_params.copy()
            test_param = { overflow_param: string_generator(int(size)) }
            body.update(test_param)

            resp2 = requests.request(url= base_path+path, method = method, params = query_params, json = body)
            if resp2.status_code == 200:
                print(f"Path : {path:20} |\t Test Case : {post_test_case} Testing payload size with {payloads[m]:25} |\t Result : Pass")
            else:
                print(f"Path : {path:20} |\t Test Case : {post_test_case} Testing payload size with {payloads[m]:25} |\t Result : Fail")
                print(resp2.status_code, resp2.content)



def main():
    file = open('api_paths.txt')
    for path in file:
        path = path.strip()
        for method in getHTTPMethod(path):
            method = method.upper()
            if method == "GET":
                if(queryExist(path,'get')):
                        #print(path)
                        query = getQueryParams(path,method.lower())
                        #fuzzing(path,method, query = query)
                        #injection(path,method,query)
                        #content_type_modification(path,method,query = query)
                else:
                    #content_type_modification(path,method)
                        print(path,method,query)
                        #print()
            if method == "POST":
                #print(path)
                if(getBodyParams(path,method)):
                    if(queryExist(path,method.lower())):
                        request_query = getQueryParams(path,method.lower())
                        request_body = getBodyParams(path,method)
                        print(path,method,request_query,request_body)
                        print()
                        #fuzzing(path,method, query = request_query, body = request_body)
                        #injection(path,method,request_query,request_body)
                        #content_type_modification(path,method,query = request_query,body = request_body)
                    else:
                        request_body = getBodyParams(path,method)
                        print(path,method,request_body)
                        print()
                        #fuzzing(path,method,body = request_body )
                        #injection(path,method,request_body)
                        #content_type_modification(path,method,body = request_body)
            if method == "DELETE":
                if(getBodyParams(path,method)):
                    if(queryExist(path,method.lower())):
                        print(path,method,request_query,request_body)
                        print()
                else:
                    request_body = getBodyParams(path,method)
                    print(path,method,request_body)
                    print()

            if method == "PUT":
                if(getBodyParams(path,method)):
                    if(queryExist(path,method.lower())):
                        print(path,method,request_query,request_body)
                        print()
                else:
                    request_body = getBodyParams(path,method)
                    print(path,method,request_body)
                    print()
def foo():
    parser = ResolvingParser('api.yml')
    p_obj = parser.specification['paths']
    for paths in p_obj:
        print(paths)

if __name__ == "__main__":
	main()
