#!/bin/bash
# ------------------------------------------------------------------------------
# put an alert in kanboard (kanboard.org)
#
# copy at /var/ossec/active-response/bin/ossec-kanboard.sh
# 
# Note that if there the <disabled> value of the last defined <active-response> 
# determines the state for all active responses within ossec.conf
# 
# Author: Stephan Leemburg
# ------------------------------------------------------------------------------
# Argumentlist:
#
# 1  action (delete or add)
# 2  user name (or - if not set)
# 3  src ip (or - if not set)
# 4  Alert id (uniq for every alert)
# 5  Rule id
# 6  Agent name/host
# 7  Filename
#
# ------------------------------------------------------------------------------
# dependencies
# ------------------------------------------------------------------------------

dependencies=("jq" "curl")

# ------------------------------------------------------------------------------
# api versioning
# ------------------------------------------------------------------------------

declare -a apiid=(
    ["getProjectByName"]=1
    ["createTask"]=2134420212
)

# ------------------------------------------------------------------------------
# for global function arg passing, bash cannot pass associative arrays
# as actual function parameters
# ------------------------------------------------------------------------------

declare -A jsonargs

BASE=$(readlink -f "$(dirname $0)/../..")

# ------------------------------------------------------------------------------
# private functions
# ------------------------------------------------------------------------------

function buildkbjson() { # method, id global::jsonargs
    local method=$1
    local id=$2
    local json key val c

    json=$(printf '{"jsonrpc": "2.0", "method": "%s", "id": %d' \
                    "$method" "${apiid[$method]}")

    c=0
    for key in ${!jsonargs[@]}
    do
        [ $c -eq 0 ] && json+=', "params": {'
        [ $c -gt 0 ] && json+=', '

        json+=$(printf '"%s": "%s"' "$key" "${jsonargs[$key]}")

        let c+=1
    done
    [ $c -gt 0 ] && json+='}'
    json+="}"

    echo $json
}

function jsonrpc() { # json
    echo "$@"|curl --noproxy '*' -s -u "jsonrpc:$KB_APIKEY" -d @- $KB_ENDPOINT
}

# ------------------------------------------------------------------------------
# our kanban api
# ------------------------------------------------------------------------------

function getprojectbyname() { # name
    jsonargs=(["name"]="$@")
    local json=$(buildkbjson getProjectByName) 

    jsonrpc "$json"|jq -r '.result.id'
}

function createtask() { # title projectid description
    jsonargs=(["title"]="$1" ["project_id"]="$2" ["description"]="$3")
    local json=$(buildkbjson createTask)

    echo "$json"
    
}

function newtask() { # projectname title description
    local projectid=$(getprojectbyname "$1")

    [[ "$projectid" =~ ^[0-9]+$ ]] && {
        jsonrpc "$(createtask "$2" "$projectid" "$3")"|jq -r '.result'
    }
}

function log() {
	echo "`date` $@" >> ${BASE}/logs/active-responses.log
}

# ------------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------------

# exit if delete is requested

[ "$1" == "delete" ] && exit 0;

[ $# -lt 5 ] && {
	log "Too few arguments"
	exit 1
}

missing=""
for i in ${dependencies[@]}
do
	which $i >/dev/null 2>&1 || missing="$missing $i"
done

[ ! -z "$missing" ] && {
	log "Dependency failure for: $missing"
	exit 1
}

[ -s "${BASE}/etc/kanboard.conf" ] || {
	log "No such file ${BASE}/etc/kanboard.conf"
	exit 1
}

# ------------------------------------------------------------------------------
# jsonout_output is unfortunately useless, as the alertid is missing...
# ------------------------------------------------------------------------------
JSONLOG=$(sed -n '/<jsonout_output>/{;s/.*>\(.*\)<\/.*/\1/p}' ${BASE}/etc/ossec.conf)

## log "Invoke: $@"

. "${BASE}/etc/kanboard.conf" 

ALERTID=$4
RULEID=$5

ALERTTIME=$(echo "$ALERTID" | cut -d  "." -f 1)
ALERTLAST=$(echo "$ALERTID" | cut -d  "." -f 2)

max=0
while read line
do
	MSG[$max]="$line"
	let max++
done < <(grep -A10 "$ALERTID" "${BASE}/logs/alerts/alerts.log"|sed '/^$/,$d')

ALERTMSG=""

# line 1: Alertid, section name
# line 2: timestamp, host->source
# line 2+n: something else
# line last: logmsg

# skip line 1 (Alert id)
for ((i=1; i<max; i++))
do
	[ $i -eq 1 ] &&  {
		HOST=$(echo ${MSG[$i]}|sed 's/.* \(.*\)->.*/\1/')
		continue
	}
	[ "${MSG[$i]:0:5}" == "Rule:" ] && {
		TITLE="${MSG[$i]}"
		continue
	} 
done

let c=max-1
ID=$(newtask "$KB_PROJECT" "${HOST}: ${TITLE}" "${MSG[$c]}")

exit 0
