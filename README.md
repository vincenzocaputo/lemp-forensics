# LEMP Memory Forensics Plugins

This repository contains a handful of Rekall Framework forensics plugins that extract information from the heap memory of the main applications of a LEMP Server.

## Description

The following plugins are provided:

- **nginx** Returns information on the last HTTP requests received by the NGINX web server, with associated HTTP responses;
- **php-fpm** Returns information on the last PHP script execution requests, received by the PHP-FPM application;
- **php-fpm-ls** Returns the list of local paths of the PHP scripts that have been executed by the web server;
- **mysqld-hist** Returns the SQL queries history of MySQL Server application<sup>1</sup>;
- **mysqld-hosts** Returns information on the remote clients which have communicated with the server<sup>1</sup>;
- **mysqld-connections** Returns information on the last connections which have been established on the server<sup>1</sup>;
- **mysqld-prep-stmts** Returns the list of prepared statements which have been defined in MySQL Server<sup>1</sup>.

<sup>1</sup> Performance Schema must have been enabled on MySQL Server

## Supported applications and versions

The plugins have been tested on the following applications<sup>2</sup>:

- NGINX 1.14.1 / 1.18.0 / 1.19.1
- PHP-FPM 7.2 / 7.4
- MySQL Server 8.0.17 / 8.0.20 / 8.0.21

<sup>2</sup> Probably, the plugins may support other versions.

## Requirements

- Python 3.7 or later
- Last version of [Rekall Framework](https://github.com/google/rekall)

## Quick Start

1. Clone this repository
```
$ git clone https://github.com/VincenzoCaputo/lemp-forensics.git
```
2. Use the `--plugin` option of Rekall Framework to load the plugins
```
$ rekall -f <memdump> --profile <profile> --plugin=lemp-forensics/lemp.py <plugin> <PID>
```

In order to use properly these plugins, you will need the followings:
- A memory dump acquired on the target system (The [AFF4](https://github.com/Velocidex/c-aff4) format is recommended)
- A valid JSON file containing the system profile
- The PID value of the nginx/php-fpm/mysqld process that you want to analyse. You can gain PIDs through the *pslist* or *pstree* plugin of Rekall Framework.
