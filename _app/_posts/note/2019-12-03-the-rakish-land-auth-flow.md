---
layout: post
title: 🔑 The Rakish-Land's Auth Flow
category: note
permalink: note/rakishland-authflow/
tags: blog_play
---

## Table of Contents
{:.no_toc}
* Table of contents
{:toc}

## Introducing the Rakish Land
{:toc #intro}
I've been working on starting a private Minecraft server these days, which is called the Rakish Land.  
Although whitelist and the Mojang account verifying is safe enough, they can neither prevent unknown players from joining our server nor synchronize player data to our own databases. Therefore, we'll introduce our own authentication flow using OAuth 2.0.

## Let’s embrace Bukkit library
{:.no_toc}
Firstly, we have to decide between developing a server mod(using Forge) or a Bukkit plugin. Apparently, using a mod requires additional steps for users to connect to our systems, which might ruin players' experience during preparation.  
**Bukkit**, a great and stable server software that provides plugin supports, is our decision to program for. We started our development based on Bukkit's APIs using pure Kotlin.

> We used Gson, OkHttp, and Retrofit to queue our network requests.

## Our auth flow
{:toc #auth-flow}
Given our website has already supported OAuth 2 authorization flows, we just need to write our plugin side part as an OAuth 2 client.  
We still want users to confirm their identity, therefore the ```Authorization Code Grant``` will be our authorization policy. All of our actions conform to the [RFC 6749](https://tools.ietf.org/html/rfc6749#page-24).  
We'll redirect new players to our authorize endpoint, use the authorization code to acquire access token and refresh token, use the access token to query players' license, then save their refresh token using [```	setMetadata​(String metadataKey, MetadataValue newMetadataValue)```](https://hub.spigotmc.org/javadocs/bukkit/org/bukkit/metadata/Metadatable.html)[^1] method provided by Bukkit SDK.  
As above, when a player joined our server, we'll check if this player has metadata of refresh token. If not, we regard this player as a new player, then we lock this player's location, inventory, experience, health, food level, and other attributes, and ask this player to authenticate.

## Creating an authorization URL
{:toc #createing-authorization-url}
Considering authorization URLs to contain ```response_type```, ```client_id```, ```redirect_uri```, ```state```, etc, these URLs will be very long for humans to type. We used our link shorten APIs to simplify these URLs to the form of ```go.ifengge.cn/x``` and keep it for a day long.  
Using a player's UUID as the ```state``` parameter has two advantages. One is that we can easily identify user's UUID when we try to request licenses, and the other reason, most importantly, we could build identical URLs for users to authorize(see how authorization URLs are built), then CloudFront[^2] could cache API's respond to save link spaces, and decrease response time.

## Receiving tokens
{:toc #receiving-token}
When a user authorized from our authorize endpoint, the authorize endpoint will redirect the user to a new URL with authorization code. We'll use this code to exchange tokens from our token endpoint, this is standard.  
We implemented a simple HTTP server integrated into the plugin jar so as to receive authorization code as the new URL mentioned above after user authorized, and the server will automatically start when Bukkit calls [onEnable()](https://hub.spigotmc.org/javadocs/bukkit/org/bukkit/plugin/java/JavaPlugin.html#onEnable--). Then we used NGINX as a reverse proxy to cast ```https://api.ifengge.cn/minecraft/login/``` to this simple server.  
Then the simple server has authorization code. In other words, our plugin has an authorization code to exchange tokens! Then we'll do it by appending this code to our request to our token endpoint, and if we succeed(User might reject the authorize request, or be blocked during the authorize flow), we get both access token and refresh token. 

##  Verifying user's eligibility
{:toc #verify-users}
We'll attach the access token to our user account APIs to check whether this user has access to our server, download Dalvik's Club ID profile, and register this player's Mojang profile to our database.  
As mentioned in [Creating an authorization URL](#createing-authorization-url), we'll store the refresh token to the player's metadata.

##  Player's data synchronizing
{:toc #data-synchronizing}
When a player with refresh token metadata joined this server again, we cannot determine whether this player is eligible immediately, but we would not bother this player until we confirmed that this player's license has expired or revoked.  
We'll do our reverify process in the background by using the refresh token from this player's metadata to exchange a new pair of a new access token and a new refresh token from the token endpoint, which is standard OAuth2 procedure as well.  
Then we reperform our request to license API and if legitimate, we'll upload this player's new login information. Otherwise, we'll remove this player's refresh token metadata, notify this player and kick this player from the server after 5 minutes, then call our unregister API with player's UUID. If this player rejoins again, he will be asked for authorization just like a new player, except that all this player’s property remains.

[^1]: Metadata are not persistent. None of them will exist after server restarts.
[^2]: We moved Minecraft and go.ifengge.cn server under the same LAN eventually, then we did some trick on the link shorten API to reuse identical links. This did reduce many response time.

