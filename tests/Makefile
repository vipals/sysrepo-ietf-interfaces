install:
	sudo sysrepoctl -i ../yang/iana-if-type@2017-01-19.yang
	sudo sysrepoctl -i ../yang/ietf-interfaces@2018-02-20.yang

list:
	sudo sysrepoctl -l

oper:
	sudo sysrepocfg -X -m ietf-interfaces -f json -d operational

desc:
	sudo sysrepocfg -Edesc.xml -m ietf-interfaces

desc2:
	sudo sysrepocfg -Edesc2.xml -m ietf-interfaces

enable:
	sudo sysrepocfg -Eenable.xml -m ietf-interfaces

disable:
	sudo sysrepocfg -Edisable.xml -m ietf-interfaces

exp:
	sudo sysrepocfg -X -m ietf-interfaces -f json
