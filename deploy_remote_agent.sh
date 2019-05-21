#!/bin/sh

# TODO remove list_gps_msg list_speed_msg

ssh yuneta@$1 "/yuneta/bin/yshutdown"
scp -p \
    /yuneta/bin/ybatch \
    /yuneta/bin/ylist \
    /yuneta/bin/ystats \
    /yuneta/bin/ycommand \
    /yuneta/bin/ytestconfig \
    /yuneta/bin/yuneta \
    /yuneta/bin/yshutdown \
    /yuneta/bin/time2date \
    /yuneta/bin/tranger_list \
    /yuneta/bin/trq_list \
    yuneta@$1:/yuneta/bin

scp -p \
    /yuneta/agent/yuneta_agent \
    yuneta@$1:/yuneta/agent

ssh yuneta@$1 "/yuneta/agent/yuneta_agent --config-file=/yuneta/agent/yuneta_agent.json --start"
