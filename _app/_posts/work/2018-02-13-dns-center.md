---
layout: post
title: PHP based DNS Panel
category: work
permalink: work/php-based-dns-panel/
tags: works_personal
scheme-text: "#000"
scheme-link: "#a73300"
scheme-hover: "#ff4e00"
scheme-code: "#a73300"
last-modified: 201801221001
css: |
  body {
    background-image: linear-gradient(to bottom, #fff500, #ff8f00);
  }

  .lightense-backdrop {
    box-sizing: border-box;
    width: 100%;
    height: 100%;
    position: fixed;
    top: 0;
    left: 0;
    overflow: hidden;
    z-index: 2147483646;
    padding: 0;
    margin: 0;
    transition: opacity 300ms ease;
    cursor: zoom-out;
    opacity: 0;
    background-color: rgba(255, 255, 255, .98);
    visibility: hidden;
  }
  
  @supports (-webkit-backdrop-filter: blur(30px)) {
    .lightense-backdrop {
      background-color: rgba(255, 255, 255, .6);
      -webkit-backdrop-filter: blur(30px);
      backdrop-filter: blur(30px);
    }
  }
  
  .lightense-wrap {
    position: relative;
    transition: transform 300ms cubic-bezier(.2, 0, .1, 1);
    z-index: 2147483647;
    pointer-events: none;
  }
  
  .lightense-target {
    cursor: zoom-in;
    transition: transform 300ms cubic-bezier(.2, 0, .1, 1);
    pointer-events: auto;
  }
  
  .lightense-open {
    cursor: zoom-out;
  }
  
  .lightense-transitioning {
    pointer-events: none;
  }
---

This is a DNS manager panel running with PowerDNS, what does this mean you can have a **Desktop and Mobile Friendly** frontend for self-hosted-DNS management.

<p class="browser"><img src="https://img.ifengge.cn/images/imageb5570.png" alt="Preview"></p>

## Features
- Wildly record types support, such as LOC, TLSA, ALIAS, DNSKEY, CAA, and what PowerDNS supports.
- Nameserver distributed in ```China and Japan```.
- CNAME Flattening for any host!
- DNSSEC support.
- Custom SOA and NS records.
- Works under both ipv4 and ipv6 network.
- Mobile devices friendly.

> Using of this panel comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

**This panel has only Chinese because I am Chinese :)**

If you want to have a try, [Register an account](https://account.ifengge.cn/register/) and use the email address you've registered to send me a mail with the message that you want to use this service.


<script type="text/javascript">
!function(e,t){"object"==typeof exports&&"object"==typeof module?module.exports=t():"function"==typeof define&&define.amd?define([],t):"object"==typeof exports?exports.Lightense=t():e.Lightense=t()}(this,function(){return function(e){function t(r){if(n[r])return n[r].exports;var o=n[r]={i:r,l:!1,exports:{}};return e[r].call(o.exports,o,o.exports,t),o.l=!0,o.exports}var n={};return t.m=e,t.c=n,t.i=function(e){return e},t.d=function(e,n,r){t.o(e,n)||Object.defineProperty(e,n,{configurable:!1,enumerable:!0,get:r})},t.n=function(e){var n=e&&e.__esModule?function(){return e.default}:function(){return e};return t.d(n,"a",n),n},t.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},t.p="",t(t.s=0)}([function(e,t,n){"use strict";var r=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},o="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e},i=function(){function e(e){switch("undefined"==typeof e?"undefined":o(e)){case"undefined":throw"You need to pass an element!";case"string":return document.querySelectorAll(e);case"object":return e}}function t(e){var t=e.length;if(t)for(var r=0;r<t;r++)n(e[r]);else n(e)}function n(e){e.src&&(e.classList.add("lightense-target"),e.addEventListener("click",function(t){return k.keyboard&&(t.metaKey||t.ctrlKey)?y.open(e.src,"_blank"):void u(this)},!1))}function i(){var e="\n.lightense-backdrop {\n  box-sizing: border-box;\n  width: 100%;\n  height: 100%;\n  position: fixed;\n  top: 0;\n  left: 0;\n  overflow: hidden;\n  z-index: "+(k.zIndex-1)+";\n  padding: 0;\n  margin: 0;\n  transition: opacity "+k.time+"ms ease;\n  cursor: zoom-out;\n  opacity: 0;\n  background-color: rgba(255, 255, 255, .98);\n  visibility: hidden;\n}\n\n@supports (-webkit-backdrop-filter: blur(30px)) {\n  .lightense-backdrop {\n    background-color: rgba(255, 255, 255, .6);\n    -webkit-backdrop-filter: blur(30px);\n    backdrop-filter: blur(30px);\n  }\n}\n\n.lightense-wrap {\n  position: relative;\n  transition: transform "+k.time+"ms "+k.cubicBezier+";\n  z-index: "+k.zIndex+";\n  pointer-events: none;\n}\n\n.lightense-target {\n  cursor: zoom-in;\n  transition: transform "+k.time+"ms "+k.cubicBezier+";\n  pointer-events: auto;\n}\n\n.lightense-open {\n  cursor: zoom-out;\n}\n\n.lightense-transitioning {\n  pointer-events: none;\n}",t=h.head||h.getElementsByTagName("head")[0],n=h.createElement("style");n.styleSheet?n.styleSheet.cssText=e:n.appendChild(h.createTextNode(e)),t.appendChild(n)}function a(){k.container=h.createElement("div"),k.container.className="lightense-backdrop",h.body.appendChild(k.container)}function s(e){var t=e.width,n=e.height,r=y.pageYOffset||h.documentElement.scrollTop||0,o=y.pageXOffset||h.documentElement.scrollLeft||0,i=k.target.getBoundingClientRect(),a=t/i.width,s=y.innerWidth||h.documentElement.clientWidth||0,c=y.innerHeight||h.documentElement.clientHeight||0,l=s-k.padding,d=c-k.padding,u=t/n,p=l/d;t<l&&n<d?k.scaleFactor=a:u<p?k.scaleFactor=d/n*a:k.scaleFactor=l/t*a;var f=s/2,g=r+c/2,m=i.left+o+i.width/2,b=i.top+r+i.height/2;k.translateX=f-m,k.translateY=g-b}function c(){k.target.classList.add("lightense-open"),k.wrap=h.createElement("div"),k.wrap.className="lightense-wrap",setTimeout(function(){k.target.style.transform="scale("+k.scaleFactor+")"},20),k.target.parentNode.insertBefore(k.wrap,k.target),k.wrap.appendChild(k.target),setTimeout(function(){k.wrap.style.transform="translate3d("+k.translateX+"px, "+k.translateY+"px, 0)"},20),k.background&&(k.container.style.backgroundColor=k.background),k.container.style.visibility="visible",setTimeout(function(){k.container.style.opacity="1"},20)}function l(){f(),k.target.classList.remove("lightense-open"),k.wrap.style.transform="",k.target.style.transform="",k.target.classList.add("lightense-transitioning"),k.container.style.opacity="",setTimeout(function(){k.container.style.visibility="",k.container.style.backgroundColor="",k.wrap.parentNode.replaceChild(k.target,k.wrap),k.target.classList.remove("lightense-transitioning")},k.time)}function d(){var e=Math.abs(k.scrollY-y.scrollY);e>=k.offset&&l()}function u(e){if(k.target=e,k.target.classList.contains("lightense-open"))return l();k.scrollY=y.scrollY,k.background=k.target.getAttribute("data-background")||!1,k.padding=k.target.getAttribute("data-padding")||v.padding;var t=new Image;t.onload=function(){s(this),c(),p()},t.src=k.target.src}function p(){y.addEventListener("keyup",g,!1),y.addEventListener("scroll",d,!1),k.container.addEventListener("click",l,!1)}function f(){y.removeEventListener("keyup",g,!1),y.removeEventListener("scroll",d,!1),k.container.removeEventListener("click",l,!1)}function g(e){e.preventDefault(),27===e.keyCode&&l()}function m(n){var o=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{};b=e(n),k=r({},v,o),i(),a(),t(b)}var b,y=window,h=document,v={time:300,padding:40,offset:40,keyboard:!0,cubicBezier:"cubic-bezier(.2, 0, .1, 1)",zIndex:2147483647},k={};return m},a=i();e.exports=a}])})
</script>
<script>window.addEventListener("load",function(){Lightense("p > img:not(.no-lightense),.lightense")},!1)</script>