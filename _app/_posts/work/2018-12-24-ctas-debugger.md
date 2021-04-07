---
layout: post
title: CTAS Debugger
category: work
permalink: work/ctas-debugger/
tags: works_community
plugin: lightense
scheme-link: "#36bd6d"
scheme-text: "#36bd6d"
---

A Debug Tool for [CTAS Student System](http://172.20.2.205.cqu.pt/ctas/). This tool includes support of both macOS and Windows, and it is ready to install in an offline environment.

### License

This program is made by [Gufeng Shen](https://gufeng.sh/about/). All rights reserved and commercial use is prohibited. 

This program is a crack of the CTAS Student System(internal-use only). As such, it is not subject to university regulations. Use at your own risk.

## Features

- Edit codes directly in the webpage
- Run instantly
- Compile/Link error outputs
- Hide everything on Windows, neither a Taskbar icon nor a console window will be displayed
- Save your outputs for 5 seconds after a successfully run, then everything will disappear again
- Copy your codes automatically
- Fix page control bar
- Multiple file problems support
- Unlock copying, selecting and context menu in every CTAS pages
- Use shortcut keys to complete your homework!
- APIs available and an iOS remote client is included. You can also custom your remote control on other platforms.

## Installation

### Windows
Run install.bat and follow the instructions to install.

> Be aware! Offline installation is only available on Windows.



### macOS
If you are a macOS user, make sure [Python 3](https://www.python.org/download/releases/3.0/) is installed on your system, then run the command below in the terminal.
```
$ pip3 install -r requirements.txt
```


## Getting Started

This is a guide only tested on [Google Chrome v70](https://dl.google.com).

1. **Before you logged in, turn on Developer Tools ( ⌥⌘I or Ctrl+Shift+I )**
2. Follow the regular steps and load a question.
3. Run \_\_main\_\_.pyw 
4. Switch to the ```Console``` Tab 
5. Change the Javascript contexts dropdown to ```IFrame - main (CPractice.aspx)```
6. Paste everything in index.min.js then press ```Enter```
7. Awala! You are a cheater now!



## Usage

#### Keymaps

Key 		  	| Function
------------ 	| ---------------------
`Q`   			| Select answer A
`W`   			| Select answer B
`E`   			| Select answer C
`R`   			| Select answer D
`T`   			| Run code
`A`   			| Previous question
`S`   			| Subsequent question
`G`   			| Navigate to bottom
`g`   			| Navigate to top


#### Select and debug

You can just copy or select something as usual. Then run and debug with Visual Studio, LLDB or something else you like.



#### Edit
You can edit codes in the webpage by just click on the code section.

CTAS-Debugger will handle your modification and write it to your clipboard automatically.



#### Run

Follow the injected message and you'll see a ```run``` button when your code is ready.