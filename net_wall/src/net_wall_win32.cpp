#include "net_wall.h"
#include <iostream>
#include <comutil.h>
#pragma comment(lib,"comsuppw.lib")
namespace net_wall {
#if WIN32
	struct net_wall_win32 :net_wall {
		FWProfile profile;
		INetFwPolicy2* pNetFwPolicy2;
		HRESULT hrComInit = S_FALSE;
	};//net_wall_win32 provide windows firewall policy (for net_wall initialization)

	struct net_wall_rule_win32 :public net_wall_rule {
		INetFwRule* rule = NULL;
	};//net_wall_rule_win32 uses windows firewall rule system
	

	static NET_FW_PROFILE_TYPE2 NETFWPROFILETYPE2FromFWProfile(FWProfile fw) {//net_wall FireWallProfile to windows firewall standard profile
		switch (fw) {
		case FWProfile::__DOMAIN:
			return NET_FW_PROFILE2_DOMAIN;
		case FWProfile::__PUBLIC:
			return NET_FW_PROFILE2_PUBLIC;
		case FWProfile::__PRIVATE:
			return NET_FW_PROFILE2_PRIVATE;
		case FWProfile::__ALL:
			return NET_FW_PROFILE2_ALL;
		default:
			return NET_FW_PROFILE_TYPE2(-1);
		}
	}
	static FWAction FWActionFromNETFWACTION(NET_FW_ACTION netFWAction) {//windows firewall profile to net_wall profile
		switch (netFWAction) {
		case NET_FW_ACTION_ALLOW:
			return FWAction::FWA_ALLOW;
		case NET_FW_ACTION_BLOCK:
			return FWAction::FWA_BLOCK;
		case NET_FW_ACTION_MAX:
			return FWAction::FWA_MAX;
		default:
			return FWAction(-1);
		}
	}
	static NET_FW_ACTION NETFWACTIONFromFWAction(FWAction action) {
		switch (action) {
		case FWAction::FWA_ALLOW:
			return NET_FW_ACTION_ALLOW;
		case FWAction::FWA_BLOCK:
			return NET_FW_ACTION_BLOCK;
		case FWAction::FWA_MAX:
			return NET_FW_ACTION_MAX;
		default:
			return NET_FW_ACTION(-1);
		}
	}

	static NET_FW_RULE_DIRECTION NETFWRULEDIRECTIONFromBound(Bound bound) {
		switch (bound) {
		case Bound::B_INBOUND:
			return NET_FW_RULE_DIRECTION::NET_FW_RULE_DIR_IN;
		case Bound::B_OUTBOUND:
			return NET_FW_RULE_DIRECTION::NET_FW_RULE_DIR_OUT;
		case Bound::B_MAX:
			return NET_FW_RULE_DIRECTION::NET_FW_RULE_DIR_MAX;
		default:
			return NET_FW_RULE_DIRECTION(-1);
		}
	}

	static Bound BoundFromNETFWRULEDIRECTION(NET_FW_RULE_DIRECTION netfwRuleDirection) {
		switch (netfwRuleDirection) {
		case NET_FW_RULE_DIR_IN:
			return Bound::B_INBOUND;
		case NET_FW_RULE_DIR_OUT:
			return Bound::B_OUTBOUND;
		case NET_FW_RULE_DIR_MAX:
			return Bound::B_MAX;
		default:
			return Bound(-1);

		}
	}

	static NET_FW_IP_PROTOCOL NETFWIPPROTOCOLFromProtocol(Protocol protoCol) {
		switch (protoCol) {
		case Protocol::TCP:
			return NET_FW_IP_PROTOCOL_TCP;
		case Protocol::UDP:
			return NET_FW_IP_PROTOCOL_UDP;
		case Protocol::ANY:
			return NET_FW_IP_PROTOCOL_ANY;
		default:
			return NET_FW_IP_PROTOCOL(-1);
		}
	}

	static Protocol ProtocolFromNETFWIPPROTOCOL(NET_FW_IP_PROTOCOL netFwIPProtocol) {
		switch (netFwIPProtocol) {
		case NET_FW_IP_PROTOCOL_TCP:
			return Protocol::TCP;
		case NET_FW_IP_PROTOCOL_UDP:
			return Protocol::UDP;
		case NET_FW_IP_PROTOCOL_ANY:
			return Protocol::ANY;
		default:
			return Protocol(-1);
		}
	}

	void NET_WALL_API NET_WALL_CALL  Initialize(net_wall** wall_all, FWProfile profile) {
		HRESULT hr = S_OK;
		net_wall_win32* wall = new net_wall_win32;
		wall->profile = profile;
		wall_all[0] = wall;
		wall->hrComInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
		if (wall->hrComInit != RPC_E_CHANGED_MODE) {
			if (FAILED(wall->hrComInit)) {
				std::cerr << "Platform/win32:CoInitializeEx failed:" << wall->hrComInit << std::endl;
				Cleanup(wall);
			}
		}
		hr = CoCreateInstance(
			__uuidof(NetFwPolicy2),
			NULL,
			CLSCTX_INPROC_SERVER,
			__uuidof(INetFwPolicy2),
			(void**)&wall->pNetFwPolicy2
		);
		if (FAILED(hr)) {
			std::cerr << "Platform/win32:CoCreateInstance for INetFwPolicy2 failed:" << hr << std::endl;
			Cleanup(wall);
		}
	}
	void NET_WALL_API NET_WALL_CALL Cleanup(net_wall* wall_glob) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		if (wall->pNetFwPolicy2 != NULL) {
			wall->pNetFwPolicy2->Release();
			wall->pNetFwPolicy2 = NULL;
		}
		if (SUCCEEDED(wall->hrComInit)) {
			wall->hrComInit = S_FALSE;
			CoUninitialize();
		}
		delete wall;
	}

	bool NET_WALL_API NET_WALL_CALL IsEnabled(net_wall* wall_glob) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		VARIANT_BOOL enabled = 0;
		if (SUCCEEDED(wall->pNetFwPolicy2->get_FirewallEnabled(NETFWPROFILETYPE2FromFWProfile(wall->profile), &enabled))) {
			return (enabled == -1) ? true : false;
		}
		return false;
	}

	void NET_WALL_API NET_WALL_CALL SetEnabled(net_wall* wall_glob, bool enabled)noexcept(false) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		VARIANT_BOOL en = (enabled == true) ? -1 : 0;
		if (SUCCEEDED(wall->pNetFwPolicy2->put_FirewallEnabled(NETFWPROFILETYPE2FromFWProfile(wall->profile), en))) {
			return;
		}
		throw permission_denied(PERMISSION_ERROR_MSG);
	}
	FWProfile NET_WALL_API NET_WALL_CALL GetProfile(net_wall* wall_glob) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		return wall->profile;
	}
#if WIN32 


	bool NET_WALL_API NET_WALL_CALL IsBlockAllInboundTraffic(net_wall* wall_glob) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		VARIANT_BOOL enabled;
		if (SUCCEEDED(wall->pNetFwPolicy2->get_BlockAllInboundTraffic(NETFWPROFILETYPE2FromFWProfile(wall->profile), &enabled))) {
			return (enabled == -1) ? true : false;
		}
		return false;
	}
	void NET_WALL_API NET_WALL_CALL SetBlockAllInboundTraffic(net_wall* wall_glob, bool enabled)noexcept(false) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		if (SUCCEEDED(wall->pNetFwPolicy2->put_BlockAllInboundTraffic(NETFWPROFILETYPE2FromFWProfile(wall->profile), (enabled == true) ? -1 : 0))) {
			return;
		}
		throw permission_denied(PERMISSION_ERROR_MSG);
	}

	FWAction NET_WALL_API NET_WALL_CALL GetDefaultInboundAction(net_wall* wall_glob) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		NET_FW_ACTION action;
		if (SUCCEEDED(wall->pNetFwPolicy2->get_DefaultInboundAction(NETFWPROFILETYPE2FromFWProfile(wall->profile), &action))) {
			return FWActionFromNETFWACTION(action);
		}
		return FWAction(-1);
	}
	void NET_WALL_API NET_WALL_CALL SetDefaultInboundAction(net_wall* wall_glob, FWAction action)noexcept(false) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		if (SUCCEEDED(wall->pNetFwPolicy2->put_DefaultInboundAction(NETFWPROFILETYPE2FromFWProfile(wall->profile), NETFWACTIONFromFWAction(action)))) {
			return;
		}
		throw permission_denied(PERMISSION_ERROR_MSG);
	}

	FWAction NET_WALL_API NET_WALL_CALL GetDefaultOutboundAction(net_wall* wall_glob) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		NET_FW_ACTION action;
		if (SUCCEEDED(wall->pNetFwPolicy2->get_DefaultOutboundAction(NETFWPROFILETYPE2FromFWProfile(wall->profile), &action))) {
			return FWActionFromNETFWACTION(action);
		}
		return FWAction(-1);
	}
	void NET_WALL_API NET_WALL_CALL SetDefaultOutboundAction(net_wall* wall_glob, FWAction action)noexcept(false) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		if (SUCCEEDED(wall->pNetFwPolicy2->put_DefaultOutboundAction(NETFWPROFILETYPE2FromFWProfile(wall->profile), NETFWACTIONFromFWAction(action)))) {
			return;
		}
		throw permission_denied(PERMISSION_ERROR_MSG);
	}

	void NET_WALL_API NET_WALL_CALL GetRule(const char* name, net_wall* wall_glob, net_wall_rule** out)noexcept(false) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		net_wall_rule_win32* rule = new net_wall_rule_win32;
		INetFwRules* rules;
		if (SUCCEEDED(wall->pNetFwPolicy2->get_Rules(&rules))) {
			BSTR bstrName = _com_util::ConvertStringToBSTR(name);
			if (rules != NULL) {
				if (SUCCEEDED(rules->Item(bstrName, &rule->rule))) {
					out[0] = rule;
					rules->Release();
					SysFreeString(bstrName);
					return;
				}
				SysFreeString(bstrName);
				delete rule;
				out[0] = NULL;
				return;
			}
			else {
				delete rule;
				out[0] = NULL;
				return;
			}
		}
		throw permission_denied();
	}

		

	void NET_WALL_API NET_WALL_CALL AddRule(net_wall* wall_glob, net_wall_rule* rl)noexcept(false) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		net_wall_rule_win32* rule = (net_wall_rule_win32*)rl;
		INetFwRules* rules;
		if (SUCCEEDED(wall->pNetFwPolicy2->get_Rules(&rules))) {
			if (rules != NULL) {
				if (SUCCEEDED(rules->Add(rule->rule))) {
					rules->Release();
					return;
				}
				rules->Release();
				throw permission_denied();
			}
		}
		throw permission_denied();
	}

	void NET_WALL_API NET_WALL_CALL RemoveRule(net_wall* wall_glob, const char* ruleName)noexcept(false) {
		BSTR name = _com_util::ConvertStringToBSTR(ruleName);
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		INetFwRules* rules;
		if (SUCCEEDED(wall->pNetFwPolicy2->get_Rules(&rules))) {
			if (SUCCEEDED(rules->Remove(name))) {
				SysFreeString(name);
				rules->Release();
				return;
			}
			SysFreeString(name);
			rules->Release();
		}
		SysFreeString(name);
		throw permission_denied();
	}


	void NET_WALL_API NET_WALL_CALL EnableGroupedRule(const char* name, net_wall* wall_glob, bool enable)noexcept(false) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		BSTR groupName = _com_util::ConvertStringToBSTR(name);
		if (SUCCEEDED(wall->pNetFwPolicy2->EnableRuleGroup(NETFWPROFILETYPE2FromFWProfile(wall->profile), groupName, (enable == true) ? -1 : 0))) {
			SysFreeString(groupName);
			return;
		}
		SysFreeString(groupName);
		throw permission_denied();
	}

	bool NET_WALL_API NET_WALL_CALL IsGroupEnabled(net_wall* wall_glob, const char* name) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		BSTR groupName = _com_util::ConvertStringToBSTR(name);
		VARIANT_BOOL enabled = 0;
		if (SUCCEEDED(wall->pNetFwPolicy2->IsRuleGroupEnabled(NETFWPROFILETYPE2FromFWProfile(wall->profile),groupName,&enabled))) {
			SysFreeString(groupName);
			return enabled == -1 ? true : false;
		}
		SysFreeString(groupName);
		return false;
	}

	bool NET_WALL_API NET_WALL_CALL IsNotificationDisabled(net_wall* wall_glob) {
		VARIANT_BOOL disabled =0;
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		if (SUCCEEDED(wall->pNetFwPolicy2->get_NotificationsDisabled(NETFWPROFILETYPE2FromFWProfile(wall->profile), &disabled))) {
			return disabled == -1 ? true : false;
		}
		return false;
	}
	void NET_WALL_API NET_WALL_CALL SetNotificationDisabled(net_wall* wall_glob, bool disabled)noexcept(false) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		if (SUCCEEDED(wall->pNetFwPolicy2->put_NotificationsDisabled(NETFWPROFILETYPE2FromFWProfile(wall->profile), disabled == true ? -1 : 0))) {
			return;
		}
		throw permission_denied();
	}

	bool NET_WALL_API NET_WALL_CALL IsUnicastResponsesToMulticastBroadcastDisabled(net_wall* wall_glob) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		VARIANT_BOOL disabled = 0;
		if (SUCCEEDED(wall->pNetFwPolicy2->get_UnicastResponsesToMulticastBroadcastDisabled(NETFWPROFILETYPE2FromFWProfile(wall->profile), &disabled))) {
			return disabled == -1 ? true : false;
		}
		return false;
	}

	void NET_WALL_API NET_WALL_CALL SetUnicastResponsesToMulticastBroadcastDisabled(net_wall* wall_glob, bool disabled)noexcept(false) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		if (SUCCEEDED(wall->pNetFwPolicy2->put_UnicastResponsesToMulticastBroadcastDisabled(NETFWPROFILETYPE2FromFWProfile(wall->profile),disabled==true?-1:0))) {
			return;
		}
		throw permission_denied();
	}

	void NET_WALL_API NET_WALL_CALL RestoreDefaultSettings(net_wall* wall_glob)noexcept(false) {
		net_wall_win32* wall = (net_wall_win32*)wall_glob;
		if (SUCCEEDED(wall->pNetFwPolicy2->RestoreLocalFirewallDefaults())) {
			return;
		}
		throw permission_denied();
	}



	/*** Rule Based Method**************/
	void NET_WALL_API NET_WALL_CALL InitializeRule(net_wall_rule** rule) {
		net_wall_rule_win32* win32fwrule = new net_wall_rule_win32;
		if (SUCCEEDED(CoCreateInstance(
			__uuidof(INetFwRule), NULL,
			CLSCTX_INPROC_SERVER,
			__uuidof(INetFwRule), (void**)&win32fwrule->rule)
		)) {
			rule[0] = win32fwrule;
			return;
		}
		win32fwrule->rule = NULL;
		throw  permission_denied();
	}
	void NET_WALL_API NET_WALL_CALL Cleanup(net_wall_rule* rule) {
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		if (win32fwrule->rule != NULL) {
			win32fwrule->rule->Release();
			win32fwrule->rule = NULL;
		}
		delete win32fwrule;
	}

	void NET_WALL_API NET_WALL_CALL GroupOfRule(net_wall_rule* rule,char** out) {
		BSTR ruleName;
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		if (SUCCEEDED(win32fwrule->rule->get_Grouping(&ruleName))) {
			out[0]=_com_util::ConvertBSTRToString(ruleName);
			SysFreeString(ruleName);
		}
	}

	void NET_WALL_API NET_WALL_CALL GetName(net_wall_rule* rule, char** out) {
		BSTR name;
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		if (SUCCEEDED(win32fwrule->rule->get_Name(&name))) {
			out[0] = _com_util::ConvertBSTRToString(name);
			SysFreeString(name);
			return;
		}
	}													  
	void NET_WALL_API NET_WALL_CALL SetName(net_wall_rule* rule, const char* name)noexcept(false) {
		BSTR rulename=_com_util::ConvertStringToBSTR(name);
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		if (SUCCEEDED(win32fwrule->rule->put_Name(rulename))) {
			SysFreeString(rulename);//In alpha mode
			return;
		}
		throw permission_denied();
	}

	void NET_WALL_API NET_WALL_CALL GetDescription(net_wall_rule* rule, char** out) {
		BSTR desc;
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		if (SUCCEEDED(win32fwrule->rule->get_Description(&desc))) {
			out[0] = _com_util::ConvertBSTRToString(desc);
			SysFreeString(desc);
			return;
		}
	}
	void NET_WALL_API NET_WALL_CALL SetDescription(net_wall_rule* rule, const char* desc)noexcept(false) {
		BSTR _desc = _com_util::ConvertStringToBSTR(desc);
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		if (SUCCEEDED(win32fwrule->rule->put_Name(_desc))) {
			SysFreeString(_desc);//In alpha mode
			return;
		}
		throw permission_denied();
	}

	void NET_WALL_API NET_WALL_CALL GetApplicationName(net_wall_rule* rule, char** out) {
		BSTR appname;
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		if (SUCCEEDED(win32fwrule->rule->get_ApplicationName(&appname))) {
			out[0] = _com_util::ConvertBSTRToString(appname);
			SysFreeString(appname);
			return;
		}
	}
	void NET_WALL_API NET_WALL_CALL SetApplicationName(net_wall_rule* rule, const char* name)noexcept(false) {
		BSTR appname = _com_util::ConvertStringToBSTR(name);
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		if (SUCCEEDED(win32fwrule->rule->put_ApplicationName(appname))) {
			SysFreeString(appname);//In alpha mode
			return;
		}
		throw permission_denied();
	}

	void NET_WALL_API NET_WALL_CALL GetServiceName(net_wall_rule* rule, char** out) {
		BSTR servicename;
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		if (SUCCEEDED(win32fwrule->rule->get_ApplicationName(&servicename))) {
			out[0] = _com_util::ConvertBSTRToString(servicename);
			SysFreeString(servicename);
			return;
		}
	}
	void NET_WALL_API NET_WALL_CALL SetServiceName(net_wall_rule* rule, const char* name)noexcept(false) {
		BSTR serviceName = _com_util::ConvertStringToBSTR(name);
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		if (SUCCEEDED(win32fwrule->rule->put_ServiceName(serviceName))) {
			SysFreeString(serviceName);//In alpha mode
			return;
		}
		throw permission_denied();
	}

	Protocol NET_WALL_API NET_WALL_CALL GetProtocol(net_wall_rule* rule) {
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		LONG prot;
		if (SUCCEEDED(win32fwrule->rule->get_Protocol(&prot))) {
			return ProtocolFromNETFWIPPROTOCOL(NET_FW_IP_PROTOCOL(prot));
		}
		return Protocol(-1);
	}
	void NET_WALL_API NET_WALL_CALL SetProtocol(net_wall_rule* rule, Protocol prot)noexcept(false) {
		net_wall_rule_win32* win32fwrule = (net_wall_rule_win32*)rule;
		NET_FW_IP_PROTOCOL protocol = NETFWIPPROTOCOLFromProtocol(prot);
		if (SUCCEEDED(win32fwrule->rule->put_Protocol(LONG(protocol)))) {
			return;
		}
		throw permission_denied();
	}


#endif
	
#endif // WIN32
}