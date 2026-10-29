_bug__killer() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="bug__killer"
                ;;
            bug__killer,advisory)
                cmd="bug__killer__subcmd__advisory"
                ;;
            bug__killer,agent)
                cmd="bug__killer__subcmd__agent"
                ;;
            bug__killer,apply)
                cmd="bug__killer__subcmd__apply"
                ;;
            bug__killer,approve)
                cmd="bug__killer__subcmd__approve"
                ;;
            bug__killer,completion)
                cmd="bug__killer__subcmd__completion"
                ;;
            bug__killer,cve-info)
                cmd="bug__killer__subcmd__cve__subcmd__info"
                ;;
            bug__killer,deepsec)
                cmd="bug__killer__subcmd__deepsec"
                ;;
            bug__killer,disclose)
                cmd="bug__killer__subcmd__disclose"
                ;;
            bug__killer,doctor)
                cmd="bug__killer__subcmd__doctor"
                ;;
            bug__killer,engine)
                cmd="bug__killer__subcmd__engine"
                ;;
            bug__killer,evidence)
                cmd="bug__killer__subcmd__evidence"
                ;;
            bug__killer,heal)
                cmd="bug__killer__subcmd__heal"
                ;;
            bug__killer,help)
                cmd="bug__killer__subcmd__help"
                ;;
            bug__killer,history)
                cmd="bug__killer__subcmd__history"
                ;;
            bug__killer,hunt)
                cmd="bug__killer__subcmd__hunt"
                ;;
            bug__killer,hunter)
                cmd="bug__killer__subcmd__hunter"
                ;;
            bug__killer,init)
                cmd="bug__killer__subcmd__init"
                ;;
            bug__killer,inventory)
                cmd="bug__killer__subcmd__inventory"
                ;;
            bug__killer,mcp)
                cmd="bug__killer__subcmd__mcp"
                ;;
            bug__killer,operator-public-key)
                cmd="bug__killer__subcmd__operator__subcmd__public__subcmd__key"
                ;;
            bug__killer,osv)
                cmd="bug__killer__subcmd__osv"
                ;;
            bug__killer,plan)
                cmd="bug__killer__subcmd__plan"
                ;;
            bug__killer,probe)
                cmd="bug__killer__subcmd__probe"
                ;;
            bug__killer,rollback)
                cmd="bug__killer__subcmd__rollback"
                ;;
            bug__killer,room)
                cmd="bug__killer__subcmd__room"
                ;;
            bug__killer,scan)
                cmd="bug__killer__subcmd__scan"
                ;;
            bug__killer,security)
                cmd="bug__killer__subcmd__security"
                ;;
            bug__killer,shell)
                cmd="bug__killer__subcmd__shell"
                ;;
            bug__killer,watch)
                cmd="bug__killer__subcmd__watch"
                ;;
            bug__killer__subcmd__advisory,help)
                cmd="bug__killer__subcmd__advisory__subcmd__help"
                ;;
            bug__killer__subcmd__advisory,status)
                cmd="bug__killer__subcmd__advisory__subcmd__status"
                ;;
            bug__killer__subcmd__advisory,sync)
                cmd="bug__killer__subcmd__advisory__subcmd__sync"
                ;;
            bug__killer__subcmd__advisory__subcmd__help,help)
                cmd="bug__killer__subcmd__advisory__subcmd__help__subcmd__help"
                ;;
            bug__killer__subcmd__advisory__subcmd__help,status)
                cmd="bug__killer__subcmd__advisory__subcmd__help__subcmd__status"
                ;;
            bug__killer__subcmd__advisory__subcmd__help,sync)
                cmd="bug__killer__subcmd__advisory__subcmd__help__subcmd__sync"
                ;;
            bug__killer__subcmd__agent,doctor)
                cmd="bug__killer__subcmd__agent__subcmd__doctor"
                ;;
            bug__killer__subcmd__agent,help)
                cmd="bug__killer__subcmd__agent__subcmd__help"
                ;;
            bug__killer__subcmd__agent,investigate)
                cmd="bug__killer__subcmd__agent__subcmd__investigate"
                ;;
            bug__killer__subcmd__agent__subcmd__help,doctor)
                cmd="bug__killer__subcmd__agent__subcmd__help__subcmd__doctor"
                ;;
            bug__killer__subcmd__agent__subcmd__help,help)
                cmd="bug__killer__subcmd__agent__subcmd__help__subcmd__help"
                ;;
            bug__killer__subcmd__agent__subcmd__help,investigate)
                cmd="bug__killer__subcmd__agent__subcmd__help__subcmd__investigate"
                ;;
            bug__killer__subcmd__deepsec,enrich)
                cmd="bug__killer__subcmd__deepsec__subcmd__enrich"
                ;;
            bug__killer__subcmd__deepsec,export)
                cmd="bug__killer__subcmd__deepsec__subcmd__export"
                ;;
            bug__killer__subcmd__deepsec,help)
                cmd="bug__killer__subcmd__deepsec__subcmd__help"
                ;;
            bug__killer__subcmd__deepsec,init)
                cmd="bug__killer__subcmd__deepsec__subcmd__init"
                ;;
            bug__killer__subcmd__deepsec,process)
                cmd="bug__killer__subcmd__deepsec__subcmd__process"
                ;;
            bug__killer__subcmd__deepsec,report)
                cmd="bug__killer__subcmd__deepsec__subcmd__report"
                ;;
            bug__killer__subcmd__deepsec,revalidate)
                cmd="bug__killer__subcmd__deepsec__subcmd__revalidate"
                ;;
            bug__killer__subcmd__deepsec,scan)
                cmd="bug__killer__subcmd__deepsec__subcmd__scan"
                ;;
            bug__killer__subcmd__deepsec,status)
                cmd="bug__killer__subcmd__deepsec__subcmd__status"
                ;;
            bug__killer__subcmd__deepsec,triage)
                cmd="bug__killer__subcmd__deepsec__subcmd__triage"
                ;;
            bug__killer__subcmd__deepsec__subcmd__help,enrich)
                cmd="bug__killer__subcmd__deepsec__subcmd__help__subcmd__enrich"
                ;;
            bug__killer__subcmd__deepsec__subcmd__help,export)
                cmd="bug__killer__subcmd__deepsec__subcmd__help__subcmd__export"
                ;;
            bug__killer__subcmd__deepsec__subcmd__help,help)
                cmd="bug__killer__subcmd__deepsec__subcmd__help__subcmd__help"
                ;;
            bug__killer__subcmd__deepsec__subcmd__help,init)
                cmd="bug__killer__subcmd__deepsec__subcmd__help__subcmd__init"
                ;;
            bug__killer__subcmd__deepsec__subcmd__help,process)
                cmd="bug__killer__subcmd__deepsec__subcmd__help__subcmd__process"
                ;;
            bug__killer__subcmd__deepsec__subcmd__help,report)
                cmd="bug__killer__subcmd__deepsec__subcmd__help__subcmd__report"
                ;;
            bug__killer__subcmd__deepsec__subcmd__help,revalidate)
                cmd="bug__killer__subcmd__deepsec__subcmd__help__subcmd__revalidate"
                ;;
            bug__killer__subcmd__deepsec__subcmd__help,scan)
                cmd="bug__killer__subcmd__deepsec__subcmd__help__subcmd__scan"
                ;;
            bug__killer__subcmd__deepsec__subcmd__help,status)
                cmd="bug__killer__subcmd__deepsec__subcmd__help__subcmd__status"
                ;;
            bug__killer__subcmd__deepsec__subcmd__help,triage)
                cmd="bug__killer__subcmd__deepsec__subcmd__help__subcmd__triage"
                ;;
            bug__killer__subcmd__disclose,draft)
                cmd="bug__killer__subcmd__disclose__subcmd__draft"
                ;;
            bug__killer__subcmd__disclose,help)
                cmd="bug__killer__subcmd__disclose__subcmd__help"
                ;;
            bug__killer__subcmd__disclose__subcmd__help,draft)
                cmd="bug__killer__subcmd__disclose__subcmd__help__subcmd__draft"
                ;;
            bug__killer__subcmd__disclose__subcmd__help,help)
                cmd="bug__killer__subcmd__disclose__subcmd__help__subcmd__help"
                ;;
            bug__killer__subcmd__engine,doctor)
                cmd="bug__killer__subcmd__engine__subcmd__doctor"
                ;;
            bug__killer__subcmd__engine,explain)
                cmd="bug__killer__subcmd__engine__subcmd__explain"
                ;;
            bug__killer__subcmd__engine,help)
                cmd="bug__killer__subcmd__engine__subcmd__help"
                ;;
            bug__killer__subcmd__engine,list)
                cmd="bug__killer__subcmd__engine__subcmd__list"
                ;;
            bug__killer__subcmd__engine,skills)
                cmd="bug__killer__subcmd__engine__subcmd__skills"
                ;;
            bug__killer__subcmd__engine__subcmd__help,doctor)
                cmd="bug__killer__subcmd__engine__subcmd__help__subcmd__doctor"
                ;;
            bug__killer__subcmd__engine__subcmd__help,explain)
                cmd="bug__killer__subcmd__engine__subcmd__help__subcmd__explain"
                ;;
            bug__killer__subcmd__engine__subcmd__help,help)
                cmd="bug__killer__subcmd__engine__subcmd__help__subcmd__help"
                ;;
            bug__killer__subcmd__engine__subcmd__help,list)
                cmd="bug__killer__subcmd__engine__subcmd__help__subcmd__list"
                ;;
            bug__killer__subcmd__engine__subcmd__help,skills)
                cmd="bug__killer__subcmd__engine__subcmd__help__subcmd__skills"
                ;;
            bug__killer__subcmd__help,advisory)
                cmd="bug__killer__subcmd__help__subcmd__advisory"
                ;;
            bug__killer__subcmd__help,agent)
                cmd="bug__killer__subcmd__help__subcmd__agent"
                ;;
            bug__killer__subcmd__help,apply)
                cmd="bug__killer__subcmd__help__subcmd__apply"
                ;;
            bug__killer__subcmd__help,approve)
                cmd="bug__killer__subcmd__help__subcmd__approve"
                ;;
            bug__killer__subcmd__help,completion)
                cmd="bug__killer__subcmd__help__subcmd__completion"
                ;;
            bug__killer__subcmd__help,cve-info)
                cmd="bug__killer__subcmd__help__subcmd__cve__subcmd__info"
                ;;
            bug__killer__subcmd__help,deepsec)
                cmd="bug__killer__subcmd__help__subcmd__deepsec"
                ;;
            bug__killer__subcmd__help,disclose)
                cmd="bug__killer__subcmd__help__subcmd__disclose"
                ;;
            bug__killer__subcmd__help,doctor)
                cmd="bug__killer__subcmd__help__subcmd__doctor"
                ;;
            bug__killer__subcmd__help,engine)
                cmd="bug__killer__subcmd__help__subcmd__engine"
                ;;
            bug__killer__subcmd__help,evidence)
                cmd="bug__killer__subcmd__help__subcmd__evidence"
                ;;
            bug__killer__subcmd__help,heal)
                cmd="bug__killer__subcmd__help__subcmd__heal"
                ;;
            bug__killer__subcmd__help,help)
                cmd="bug__killer__subcmd__help__subcmd__help"
                ;;
            bug__killer__subcmd__help,history)
                cmd="bug__killer__subcmd__help__subcmd__history"
                ;;
            bug__killer__subcmd__help,hunt)
                cmd="bug__killer__subcmd__help__subcmd__hunt"
                ;;
            bug__killer__subcmd__help,hunter)
                cmd="bug__killer__subcmd__help__subcmd__hunter"
                ;;
            bug__killer__subcmd__help,init)
                cmd="bug__killer__subcmd__help__subcmd__init"
                ;;
            bug__killer__subcmd__help,inventory)
                cmd="bug__killer__subcmd__help__subcmd__inventory"
                ;;
            bug__killer__subcmd__help,mcp)
                cmd="bug__killer__subcmd__help__subcmd__mcp"
                ;;
            bug__killer__subcmd__help,operator-public-key)
                cmd="bug__killer__subcmd__help__subcmd__operator__subcmd__public__subcmd__key"
                ;;
            bug__killer__subcmd__help,osv)
                cmd="bug__killer__subcmd__help__subcmd__osv"
                ;;
            bug__killer__subcmd__help,plan)
                cmd="bug__killer__subcmd__help__subcmd__plan"
                ;;
            bug__killer__subcmd__help,probe)
                cmd="bug__killer__subcmd__help__subcmd__probe"
                ;;
            bug__killer__subcmd__help,rollback)
                cmd="bug__killer__subcmd__help__subcmd__rollback"
                ;;
            bug__killer__subcmd__help,room)
                cmd="bug__killer__subcmd__help__subcmd__room"
                ;;
            bug__killer__subcmd__help,scan)
                cmd="bug__killer__subcmd__help__subcmd__scan"
                ;;
            bug__killer__subcmd__help,security)
                cmd="bug__killer__subcmd__help__subcmd__security"
                ;;
            bug__killer__subcmd__help,shell)
                cmd="bug__killer__subcmd__help__subcmd__shell"
                ;;
            bug__killer__subcmd__help,watch)
                cmd="bug__killer__subcmd__help__subcmd__watch"
                ;;
            bug__killer__subcmd__help__subcmd__advisory,status)
                cmd="bug__killer__subcmd__help__subcmd__advisory__subcmd__status"
                ;;
            bug__killer__subcmd__help__subcmd__advisory,sync)
                cmd="bug__killer__subcmd__help__subcmd__advisory__subcmd__sync"
                ;;
            bug__killer__subcmd__help__subcmd__agent,doctor)
                cmd="bug__killer__subcmd__help__subcmd__agent__subcmd__doctor"
                ;;
            bug__killer__subcmd__help__subcmd__agent,investigate)
                cmd="bug__killer__subcmd__help__subcmd__agent__subcmd__investigate"
                ;;
            bug__killer__subcmd__help__subcmd__deepsec,enrich)
                cmd="bug__killer__subcmd__help__subcmd__deepsec__subcmd__enrich"
                ;;
            bug__killer__subcmd__help__subcmd__deepsec,export)
                cmd="bug__killer__subcmd__help__subcmd__deepsec__subcmd__export"
                ;;
            bug__killer__subcmd__help__subcmd__deepsec,init)
                cmd="bug__killer__subcmd__help__subcmd__deepsec__subcmd__init"
                ;;
            bug__killer__subcmd__help__subcmd__deepsec,process)
                cmd="bug__killer__subcmd__help__subcmd__deepsec__subcmd__process"
                ;;
            bug__killer__subcmd__help__subcmd__deepsec,report)
                cmd="bug__killer__subcmd__help__subcmd__deepsec__subcmd__report"
                ;;
            bug__killer__subcmd__help__subcmd__deepsec,revalidate)
                cmd="bug__killer__subcmd__help__subcmd__deepsec__subcmd__revalidate"
                ;;
            bug__killer__subcmd__help__subcmd__deepsec,scan)
                cmd="bug__killer__subcmd__help__subcmd__deepsec__subcmd__scan"
                ;;
            bug__killer__subcmd__help__subcmd__deepsec,status)
                cmd="bug__killer__subcmd__help__subcmd__deepsec__subcmd__status"
                ;;
            bug__killer__subcmd__help__subcmd__deepsec,triage)
                cmd="bug__killer__subcmd__help__subcmd__deepsec__subcmd__triage"
                ;;
            bug__killer__subcmd__help__subcmd__disclose,draft)
                cmd="bug__killer__subcmd__help__subcmd__disclose__subcmd__draft"
                ;;
            bug__killer__subcmd__help__subcmd__engine,doctor)
                cmd="bug__killer__subcmd__help__subcmd__engine__subcmd__doctor"
                ;;
            bug__killer__subcmd__help__subcmd__engine,explain)
                cmd="bug__killer__subcmd__help__subcmd__engine__subcmd__explain"
                ;;
            bug__killer__subcmd__help__subcmd__engine,list)
                cmd="bug__killer__subcmd__help__subcmd__engine__subcmd__list"
                ;;
            bug__killer__subcmd__help__subcmd__engine,skills)
                cmd="bug__killer__subcmd__help__subcmd__engine__subcmd__skills"
                ;;
            bug__killer__subcmd__help__subcmd__hunter,candidate)
                cmd="bug__killer__subcmd__help__subcmd__hunter__subcmd__candidate"
                ;;
            bug__killer__subcmd__help__subcmd__hunter,hunt)
                cmd="bug__killer__subcmd__help__subcmd__hunter__subcmd__hunt"
                ;;
            bug__killer__subcmd__help__subcmd__hunter,plan)
                cmd="bug__killer__subcmd__help__subcmd__hunter__subcmd__plan"
                ;;
            bug__killer__subcmd__help__subcmd__hunter,run)
                cmd="bug__killer__subcmd__help__subcmd__hunter__subcmd__run"
                ;;
            bug__killer__subcmd__help__subcmd__hunter,verify)
                cmd="bug__killer__subcmd__help__subcmd__hunter__subcmd__verify"
                ;;
            bug__killer__subcmd__help__subcmd__mcp,config)
                cmd="bug__killer__subcmd__help__subcmd__mcp__subcmd__config"
                ;;
            bug__killer__subcmd__help__subcmd__mcp,serve)
                cmd="bug__killer__subcmd__help__subcmd__mcp__subcmd__serve"
                ;;
            bug__killer__subcmd__help__subcmd__room,evidence)
                cmd="bug__killer__subcmd__help__subcmd__room__subcmd__evidence"
                ;;
            bug__killer__subcmd__help__subcmd__room,plan)
                cmd="bug__killer__subcmd__help__subcmd__room__subcmd__plan"
                ;;
            bug__killer__subcmd__help__subcmd__room,status)
                cmd="bug__killer__subcmd__help__subcmd__room__subcmd__status"
                ;;
            bug__killer__subcmd__help__subcmd__security,catalog)
                cmd="bug__killer__subcmd__help__subcmd__security__subcmd__catalog"
                ;;
            bug__killer__subcmd__help__subcmd__security,coverage)
                cmd="bug__killer__subcmd__help__subcmd__security__subcmd__coverage"
                ;;
            bug__killer__subcmd__help__subcmd__security,explain)
                cmd="bug__killer__subcmd__help__subcmd__security__subcmd__explain"
                ;;
            bug__killer__subcmd__help__subcmd__security,fix)
                cmd="bug__killer__subcmd__help__subcmd__security__subcmd__fix"
                ;;
            bug__killer__subcmd__help__subcmd__security,guidance)
                cmd="bug__killer__subcmd__help__subcmd__security__subcmd__guidance"
                ;;
            bug__killer__subcmd__help__subcmd__security,scan)
                cmd="bug__killer__subcmd__help__subcmd__security__subcmd__scan"
                ;;
            bug__killer__subcmd__help__subcmd__security,status)
                cmd="bug__killer__subcmd__help__subcmd__security__subcmd__status"
                ;;
            bug__killer__subcmd__help__subcmd__security,verify)
                cmd="bug__killer__subcmd__help__subcmd__security__subcmd__verify"
                ;;
            bug__killer__subcmd__hunter,candidate)
                cmd="bug__killer__subcmd__hunter__subcmd__candidate"
                ;;
            bug__killer__subcmd__hunter,help)
                cmd="bug__killer__subcmd__hunter__subcmd__help"
                ;;
            bug__killer__subcmd__hunter,hunt)
                cmd="bug__killer__subcmd__hunter__subcmd__hunt"
                ;;
            bug__killer__subcmd__hunter,plan)
                cmd="bug__killer__subcmd__hunter__subcmd__plan"
                ;;
            bug__killer__subcmd__hunter,run)
                cmd="bug__killer__subcmd__hunter__subcmd__run"
                ;;
            bug__killer__subcmd__hunter,verify)
                cmd="bug__killer__subcmd__hunter__subcmd__verify"
                ;;
            bug__killer__subcmd__hunter__subcmd__help,candidate)
                cmd="bug__killer__subcmd__hunter__subcmd__help__subcmd__candidate"
                ;;
            bug__killer__subcmd__hunter__subcmd__help,help)
                cmd="bug__killer__subcmd__hunter__subcmd__help__subcmd__help"
                ;;
            bug__killer__subcmd__hunter__subcmd__help,hunt)
                cmd="bug__killer__subcmd__hunter__subcmd__help__subcmd__hunt"
                ;;
            bug__killer__subcmd__hunter__subcmd__help,plan)
                cmd="bug__killer__subcmd__hunter__subcmd__help__subcmd__plan"
                ;;
            bug__killer__subcmd__hunter__subcmd__help,run)
                cmd="bug__killer__subcmd__hunter__subcmd__help__subcmd__run"
                ;;
            bug__killer__subcmd__hunter__subcmd__help,verify)
                cmd="bug__killer__subcmd__hunter__subcmd__help__subcmd__verify"
                ;;
            bug__killer__subcmd__mcp,config)
                cmd="bug__killer__subcmd__mcp__subcmd__config"
                ;;
            bug__killer__subcmd__mcp,help)
                cmd="bug__killer__subcmd__mcp__subcmd__help"
                ;;
            bug__killer__subcmd__mcp,serve)
                cmd="bug__killer__subcmd__mcp__subcmd__serve"
                ;;
            bug__killer__subcmd__mcp__subcmd__help,config)
                cmd="bug__killer__subcmd__mcp__subcmd__help__subcmd__config"
                ;;
            bug__killer__subcmd__mcp__subcmd__help,help)
                cmd="bug__killer__subcmd__mcp__subcmd__help__subcmd__help"
                ;;
            bug__killer__subcmd__mcp__subcmd__help,serve)
                cmd="bug__killer__subcmd__mcp__subcmd__help__subcmd__serve"
                ;;
            bug__killer__subcmd__room,evidence)
                cmd="bug__killer__subcmd__room__subcmd__evidence"
                ;;
            bug__killer__subcmd__room,help)
                cmd="bug__killer__subcmd__room__subcmd__help"
                ;;
            bug__killer__subcmd__room,plan)
                cmd="bug__killer__subcmd__room__subcmd__plan"
                ;;
            bug__killer__subcmd__room,status)
                cmd="bug__killer__subcmd__room__subcmd__status"
                ;;
            bug__killer__subcmd__room__subcmd__help,evidence)
                cmd="bug__killer__subcmd__room__subcmd__help__subcmd__evidence"
                ;;
            bug__killer__subcmd__room__subcmd__help,help)
                cmd="bug__killer__subcmd__room__subcmd__help__subcmd__help"
                ;;
            bug__killer__subcmd__room__subcmd__help,plan)
                cmd="bug__killer__subcmd__room__subcmd__help__subcmd__plan"
                ;;
            bug__killer__subcmd__room__subcmd__help,status)
                cmd="bug__killer__subcmd__room__subcmd__help__subcmd__status"
                ;;
            bug__killer__subcmd__security,catalog)
                cmd="bug__killer__subcmd__security__subcmd__catalog"
                ;;
            bug__killer__subcmd__security,coverage)
                cmd="bug__killer__subcmd__security__subcmd__coverage"
                ;;
            bug__killer__subcmd__security,explain)
                cmd="bug__killer__subcmd__security__subcmd__explain"
                ;;
            bug__killer__subcmd__security,fix)
                cmd="bug__killer__subcmd__security__subcmd__fix"
                ;;
            bug__killer__subcmd__security,guidance)
                cmd="bug__killer__subcmd__security__subcmd__guidance"
                ;;
            bug__killer__subcmd__security,help)
                cmd="bug__killer__subcmd__security__subcmd__help"
                ;;
            bug__killer__subcmd__security,scan)
                cmd="bug__killer__subcmd__security__subcmd__scan"
                ;;
            bug__killer__subcmd__security,status)
                cmd="bug__killer__subcmd__security__subcmd__status"
                ;;
            bug__killer__subcmd__security,verify)
                cmd="bug__killer__subcmd__security__subcmd__verify"
                ;;
            bug__killer__subcmd__security__subcmd__help,catalog)
                cmd="bug__killer__subcmd__security__subcmd__help__subcmd__catalog"
                ;;
            bug__killer__subcmd__security__subcmd__help,coverage)
                cmd="bug__killer__subcmd__security__subcmd__help__subcmd__coverage"
                ;;
            bug__killer__subcmd__security__subcmd__help,explain)
                cmd="bug__killer__subcmd__security__subcmd__help__subcmd__explain"
                ;;
            bug__killer__subcmd__security__subcmd__help,fix)
                cmd="bug__killer__subcmd__security__subcmd__help__subcmd__fix"
                ;;
            bug__killer__subcmd__security__subcmd__help,guidance)
                cmd="bug__killer__subcmd__security__subcmd__help__subcmd__guidance"
                ;;
            bug__killer__subcmd__security__subcmd__help,help)
                cmd="bug__killer__subcmd__security__subcmd__help__subcmd__help"
                ;;
            bug__killer__subcmd__security__subcmd__help,scan)
                cmd="bug__killer__subcmd__security__subcmd__help__subcmd__scan"
                ;;
            bug__killer__subcmd__security__subcmd__help,status)
                cmd="bug__killer__subcmd__security__subcmd__help__subcmd__status"
                ;;
            bug__killer__subcmd__security__subcmd__help,verify)
                cmd="bug__killer__subcmd__security__subcmd__help__subcmd__verify"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        bug__killer)
            opts="-h -V --help --version shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__advisory)
            opts="-h --help sync status help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__advisory__subcmd__help)
            opts="sync status help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__advisory__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__advisory__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__advisory__subcmd__help__subcmd__sync)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__advisory__subcmd__status)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__advisory__subcmd__sync)
            opts="-h --offline-cache --sources --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --offline-cache)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sources)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__agent)
            opts="-h --help doctor investigate help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__agent__subcmd__doctor)
            opts="-h --provider --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --provider)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__agent__subcmd__help)
            opts="doctor investigate help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__agent__subcmd__help__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__agent__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__agent__subcmd__help__subcmd__investigate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__agent__subcmd__investigate)
            opts="-h --provider --model --mode --max-steps --export-profile --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --provider)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --model)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-steps)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --export-profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__apply)
            opts="-h --approval-file --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --approval-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__approve)
            opts="-h --approver --validity-mins --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --approver)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --validity-mins)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__completion)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__cve__subcmd__info)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec)
            opts="-h --help init scan process revalidate triage enrich report export status help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__enrich)
            opts="-h --project-id --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --project-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__export)
            opts="-h --project-id --format --out --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --project-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__help)
            opts="init scan process revalidate triage enrich report export status help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__help__subcmd__enrich)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__help__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__help__subcmd__init)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__help__subcmd__process)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__help__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__help__subcmd__revalidate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__help__subcmd__scan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__help__subcmd__triage)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__init)
            opts="-h --project-id --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --project-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__process)
            opts="-h --project-id --batch-size --limit --filter --max-cost-usd --model --agent --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --project-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --batch-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-cost-usd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --model)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --agent)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__report)
            opts="-h --project-id --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --project-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__revalidate)
            opts="-h --project-id --force --model --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --project-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --model)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__scan)
            opts="-h --project-id --filter --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --project-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__status)
            opts="-h --project-id --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --project-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__deepsec__subcmd__triage)
            opts="-h --project-id --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --project-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__disclose)
            opts="-h --help draft help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__disclose__subcmd__draft)
            opts="-h --private --output --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__disclose__subcmd__help)
            opts="draft help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__disclose__subcmd__help__subcmd__draft)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__disclose__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__doctor)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__engine)
            opts="-h --help doctor list explain skills help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__engine__subcmd__doctor)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__engine__subcmd__explain)
            opts="-h --goal --target --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --goal)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --target)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__engine__subcmd__help)
            opts="doctor list explain skills help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__engine__subcmd__help__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__engine__subcmd__help__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__engine__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__engine__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__engine__subcmd__help__subcmd__skills)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__engine__subcmd__list)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__engine__subcmd__skills)
            opts="-h --filter --id --cve --query --limit --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cve)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --query)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__evidence)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__heal)
            opts="-h --dry-run --apply --auto-apply --rules --osv --allow-untrusted-rules --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --rules)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help)
            opts="shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__advisory)
            opts="sync status"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__advisory__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__advisory__subcmd__sync)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__agent)
            opts="doctor investigate"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__agent__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__agent__subcmd__investigate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__apply)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__approve)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__completion)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__cve__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__deepsec)
            opts="init scan process revalidate triage enrich report export status"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__deepsec__subcmd__enrich)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__deepsec__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__deepsec__subcmd__init)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__deepsec__subcmd__process)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__deepsec__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__deepsec__subcmd__revalidate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__deepsec__subcmd__scan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__deepsec__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__deepsec__subcmd__triage)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__disclose)
            opts="draft"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__disclose__subcmd__draft)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__engine)
            opts="doctor list explain skills"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__engine__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__engine__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__engine__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__engine__subcmd__skills)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__evidence)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__heal)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__history)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__hunt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__hunter)
            opts="hunt plan run candidate verify"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__hunter__subcmd__candidate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__hunter__subcmd__hunt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__hunter__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__hunter__subcmd__run)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__hunter__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__init)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__inventory)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__mcp)
            opts="serve config"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__mcp__subcmd__config)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__mcp__subcmd__serve)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__operator__subcmd__public__subcmd__key)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__osv)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__probe)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__rollback)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__room)
            opts="plan status evidence"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__room__subcmd__evidence)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__room__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__room__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__scan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__security)
            opts="scan coverage status explain fix verify guidance catalog"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__security__subcmd__catalog)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__security__subcmd__coverage)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__security__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__security__subcmd__fix)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__security__subcmd__guidance)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__security__subcmd__scan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__security__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__security__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__shell)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__help__subcmd__watch)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__history)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunt)
            opts="-h --max-hypotheses --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --max-hypotheses)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter)
            opts="-h --help hunt plan run candidate verify help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__candidate)
            opts="-h --evidence --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__help)
            opts="hunt plan run candidate verify help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__help__subcmd__candidate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__help__subcmd__hunt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__help__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__help__subcmd__run)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__help__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__hunt)
            opts="-h --max-hypotheses --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --max-hypotheses)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__plan)
            opts="-h --policy --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --policy)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__run)
            opts="-h --plan --sandbox-only --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --plan)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__hunter__subcmd__verify)
            opts="-h --offline --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__init)
            opts="-h --hooks --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --hooks)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__inventory)
            opts="-h --sbom --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__mcp)
            opts="-h --help serve config help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__mcp__subcmd__config)
            opts="-h --host --binary --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --host)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --binary)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__mcp__subcmd__help)
            opts="serve config help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__mcp__subcmd__help__subcmd__config)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__mcp__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__mcp__subcmd__help__subcmd__serve)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__mcp__subcmd__serve)
            opts="-h --transport --read-only --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --transport)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__operator__subcmd__public__subcmd__key)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__osv)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__plan)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__probe)
            opts="-t -h --json --timeout --sensitive-paths --authorized --allow-private-targets --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -t)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__rollback)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__room)
            opts="-h --help plan status evidence help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__room__subcmd__evidence)
            opts="-h --include-gaps --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__room__subcmd__help)
            opts="plan status evidence help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__room__subcmd__help__subcmd__evidence)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__room__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__room__subcmd__help__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__room__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__room__subcmd__plan)
            opts="-h --goal --profile --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --goal)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__room__subcmd__status)
            opts="-h --receipts --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__scan)
            opts="-h --json --check-runtime --rules --osv --taint --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --rules)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security)
            opts="-h --help scan coverage status explain fix verify guidance catalog help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__catalog)
            opts="-h --category --status --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --category)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --status)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__coverage)
            opts="-h --per-rule --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__explain)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__fix)
            opts="-h --plan --apply --receipt --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --receipt)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__guidance)
            opts="-h --language --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --language)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__help)
            opts="scan coverage status explain fix verify guidance catalog help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__help__subcmd__catalog)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__help__subcmd__coverage)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__help__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__help__subcmd__fix)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__help__subcmd__guidance)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__help__subcmd__scan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__help__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__scan)
            opts="-h --profile --changed-only --staged --fail-on --osv --report-version --exit-contract --engine --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --profile)
                    COMPREPLY=($(compgen -W "quick project ci deep" -- "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -W "critical high medium low" -- "${cur}"))
                    return 0
                    ;;
                --report-version)
                    COMPREPLY=($(compgen -W "1 2" -- "${cur}"))
                    return 0
                    ;;
                --exit-contract)
                    COMPREPLY=($(compgen -W "v1 v2" -- "${cur}"))
                    return 0
                    ;;
                --engine)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__status)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__security__subcmd__verify)
            opts="-h --json --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__shell)
            opts="-h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        bug__subcmd__killer__subcmd__watch)
            opts="-i -h --interval --auto-heal --rules --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --interval)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -i)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rules)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _bug__killer -o nosort -o bashdefault -o default bug-killer
else
    complete -F _bug__killer -o bashdefault -o default bug-killer
fi
