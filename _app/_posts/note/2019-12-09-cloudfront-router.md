---
layout: post
title: ☁ CloudFront Origin Router
category: note
permalink: note/cloudfront-origin-router/
tags: blog_play
---

CloudFront delivers websites to users from the nearest locations. Meanwhile, it forward requests that are not cached or not permitted to be cached to your origin servers. However, it is not flexible enough and neither smart enough since it cannot automatically decide the fastest origin based on the response time from edge nodes to origin servers, cannot differentiate execution timeout and connect timeout, etc.

## Lambda × CloudFront
AWS has a service called Lambda which offers a serverless script execution environment. When you bring it to CloudFront, with replication on every edge node, it is called Lambda@Edge. Then you can use a script to amend requests before CloudFront sends it to the original server.
> Lambda@Edge only supports[^1] `nodejs8.10`, `nodejs10.x`, or `python3.7` even though Go and other languages can be uploaded on the setup page. Besides, Lambda@Edge has only one second of execution time.
  
To start, given that Lambda@Edge is a form of AWS Lambda, you can use the examples illustrated in [Building Lambda Functions with Python](https://docs.aws.amazon.com/lambda/latest/dg/python-programming-model.html). It is worth noting that the parameter `event` has a structure defined here: [Lambda@Edge Event Structure](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-event-structure.html).  
```python
def handler(event, context):
    request = event['Records'][0]['cf']['request']
    return request
```

Then define a const array that holds all available origins:
```python
SERVERS = [
    {"host": "o1.example.com", "port": 443},
    {"host": "o2.example.com", "port": 443},
    ...
]
```

You can make a simple HTTP request to determine the fastest origin by using the following code:
```python
# s: Server Object
def evaluate(s):
    try:
        connection = http.client.HTTPConnection(s['host'], s['port'], timeout=0.8)
        connection.request("HEAD", "/")
        connection.getresponse()
    except:
        print("[Down] unreachable host:" + s['host'])
        return
    print("[OK] reachable host:" + s['host'])
    ... pushlish result
```
Better use a multithreading model since there is a time limit:
```python
for server in SERVERS:
    threading.Thread(target=evaluate, args=(server,)).start()
```
You may need a watchdog so as to avoid timeout:
```python
def guard():
    time.sleep(0.9)
    ... publish a default server
```
```python
threading.Thread(target=guard).start()
```

After this, you have to implement a listener that only accept the first result from all threads, and finally, redirect the request to the fastest responder in the handler:
```python
request["origin"]["custom"]["domainName"] = choice["host"]
request["origin"]["custom"]["port"] = choice["port"]
```

You might not have to determine the fastest one each time when CloudFront is about to initiate a connection to an original server, so you have to make sure that you implemented a caching mechanism. 


## Performances
Once this is deployed you can view logs in the CloudWatch console.

`1ms` for common situations

![5e7bc941389a060b9dd929ece54ba406.png]({{ site.file }}/5e7bc941389a060b9dd929ece54ba406.png){: .size-small}  

`800+ms` to update cached origin

![5a80397f4b5bd92b601a27af966771b1.png]({{ site.file }}/5a80397f4b5bd92b601a27af966771b1.png){: .size-small}  

`900+ms` when all origins are not reachable(result advocated by watchdog)

![97e6862a1790a859f52349c879cbbbc6.png]({{ site.file }}/97e6862a1790a859f52349c879cbbbc6.png){: .size-small}  


[^1]: See [Lambda Function Configuration and Execution Environment](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-requirements-limits.html#lambda-requirements-lambda-function-configuration)
