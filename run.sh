#!/bin/bash

./build.sh -r && echo && cd build && ./deploy_vulnerable && ./deploy_attackers && ./setup_vulnerable && ./execute_attack && cd ..
