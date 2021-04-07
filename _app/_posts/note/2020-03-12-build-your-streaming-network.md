---
layout: post
title: 🛰 Build your own live network!
category: note
permalink: note/live-network/
tags: notes
---

## Under the hood
When you clicked the start button to push your stream from streaming software like OBS, XSplit Broadcaster, they push your screen generally via RTMP[^1] to the server.

Since we cannot play RTMP stream directly via video tag in HTML5, what we are going to do is to save every video fragment from RTMP stream and generate an HLS[^2] playlist. There will be many `.ts` files containing every fragment of videos and a `.m3u8` file revealing `ts` files to be played in the future. 

To deliver these ts and m3u8 files, we can use simple HTTP.

Now the structure is pretty simple:

OBS | --- RTMP ---> | Server | --- HTTP ---> | Browsers

## Nginx with RTMP support
**[nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module)** is an Nginx module that provides RTMP support to Nginx.

We can compile an Nginx module via this:
```sh
./configure --add-dynamic-module=/path/to/nginx-rtmp-module
```

After loading the module, we can work with Nginx config. Here is an example:
```nginx
rtmp {
    server {
        listen 1935;
        chunk_size 4000;
        buflen 500ms;
        
        application live {
                live on;
                allow play 10.20.0.0/16;
                deny play all;

                on_publish http://live-control.ifengge.cn:80/publish/;
                on_publish_done http://live-control.ifengge.cn:80/done/;

                record all;
                record_path /path/to/live/rec/;

                hls on;
                hls_path /path/to/live/streams/;

                hls_fragment 1;
                hls_playlist_length 10;

                hls_nested on;
                hls_fragment_naming system;
        }
  }
}
```
With the stream key, the final URL will be like `rtmp://ip:1935/live/key` (e.g., put `rtmp://ip:1935/live` in the server field, and `key` in the key field in XSplit), and it will be validated by `on_publish` directive, see the module docs to find out.

After we clicked the push button, we can immediately see several `.ts` files and an `index.m3u8` file in `/path/to/live/streams/key`. 

⚠️ The playlist file is changing every time, therefore it cannot be cached.

## Serve contents
Create a host to this streaming folder like this:
```nginx
server {
        include  confincludes/conf/listen.https.conf;
        server_name  live-content.example.com;

        location ~ ^/streams/(\w+/\w+\.m3u8)$ {
                alias /path/to/live/streams/$1;
                add_header Access-Control-Allow-Origin 'https://live.ifengge.cn';
                add_header Access-Control-Allow-Methods 'GET, OPTIONS';

                expires -1;
        }

        location ~ ^/streams/(\w+/\w+\.ts)$ {
                alias /path/to/live/streams/$1;
                add_header Access-Control-Allow-Origin 'https://live.ifengge.cn';
                add_header Access-Control-Allow-Methods 'GET, OPTIONS';

                expires max;
        }

        location ~ ^/rec/(\w+\.flv)$ {
                alias /path/to/live/rec/$1;
                add_header Access-Control-Allow-Origin 'https://live.ifengge.cn';
                add_header Access-Control-Allow-Methods 'GET, OPTIONS';

                expires max;
        }
}
```

## Webplayer and Danmaku
Some browsers support HLS natively, while some are not. However, we can always use [hls.js](https://github.com/video-dev/hls.js/) to tackle this.

To provide danmaku support, you have to implement a websocket server.

## About Playstations
I'm using a USG as my gateway. The `gateway.config.json` solution from ubnt is somewhat complicated.
I managed to do it by directly casting `live-*.twitch.tv` from DNS to my rtmp server.

[^1]: See the whitepaper here: [rtmp_specification_1.0.pdf](https://wwwimages2.adobe.com/content/dam/acom/en/devnet/rtmp/pdf/rtmp_specification_1.0.pdf)
[^2]: [RFC 8216 - HTTP Live Streaming](https://tools.ietf.org/html/rfc8216)