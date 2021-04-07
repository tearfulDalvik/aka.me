---
layout: post
title: Calendarista
category: work
permalink: work/calendarista/
tags: works_personal
scheme-link: "#ff3f00"
scheme-text: "#ff3f00"
---

## Intro
This tool will provide you a way to subscribe to students' class schedules on your calendar on PCs, mailboxes or iCloud devices. Thereby you can get informed about forthcoming classes via notification, including the professor's name, classroom it will take place and the exact time.

Also, subscribing to a calendar means classes can be auto-updated. You will never bother with semester changes or temporary class adjustments as long as they are updated by the academic affairs office.

As an inadvertent advantage, students can subscribe to multiple class tables with one device, therefore you can add with your friend's schedule together and compare leisures easily.

## Under the hood
The working mechanism is quite straightforward. The server will simply return an iCalendar[^1] file contains all your class schedules over the semester.
Your calendar provider will re-download this iCalendar file periodically in order to provide you an updated schedule.

## Further Usages
Benefited by integrating the schedule into the iOS calendar, I found there are many feasible ways to exploit usages:
- I can synchronize schedules and along with their alarms with Apple Watch and Mac without any additional setup.
- I can ask HomePod about the next class.
- It is very convenient to share the entire schedule with friends, who can preview it in Safari without adding.
- Collaborating with Shortcuts.app makes things easier. I created a [shortcut](https://www.icloud.com/shortcuts/281c37cf09e3450e9ae98782448ae55a) to set a wakeup alarm based on the time of the first class of the next day.
- It is separated from other schedules, therefore you can control the visibility of class schedules in your calendar. Additionally, you can retrieve schedules using [```EKEventStore.calendar(withIdentifier:)```](https://developer.apple.com/documentation/eventkit/ekeventstore) if you are going to develop your own app.

## Usage
[View on Dalvik's API Docs](https://docs.ifengge.cn/display/site/CQUPT+APIs)
{: .largetype}

[^1]: [iCalendar - Wikipedia](https://en.wikipedia.org/wiki/ICalendar)