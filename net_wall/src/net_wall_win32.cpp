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
	};

	struct net_wall_rule_win32 :public net_wall_rule {
		INetFwRule* rule = NULL;
	};
	

	static NET_FW_PROFILE_TYPE2 NETFWPROFILETYPE2FromFWProfile(FWProfile fw) {
		switch (fw) {
		case __DOMAIN:
			return NET_FW_PROFILE2_DOMAIN;
		case __PUBLIC:
			return NET_FW_PROFILE2_PUBLIC;
		case __PRIVATE:
			return NET_FW_PROFILE2_PRIVATE;
		case __ALL:
			return NET_FW_PROFILE2_ALL;
		default:
			return NET_FW_PROFILE_TYPE2(-1);
		}
	}
	static FWAction FWActionFromNETFWACTION(NET_FW_ACTION netFWAction) {
		switch (netFWAction) {
		case NET_FW_ACTION_ALLOW:
			return FWAction::ALLOW;
		case NET_FW_ACTION_BLOCK:
			return FWAction::BLOCK;
		case NET_FW_ACTION_MAX:
			return FWAction::MAX;
		default:
			return FWAction(-1);
		}
	}
	static NET_FW_ACTION NETFWACTIONFromFWAction(FWAction action) {
		switch (action) {
		case ALLOW:
			return NET_FW_ACTION_ALLOW;
		case BLOCK:
			return NET_FW_ACTION_BLOCK;
		case MAX:
			return NET_FW_ACTION_MAX;
		default:
			return NET_FW_ACTION(-1);
		}
	}
	extern "C++" {

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

		void NET_WALL_API NET_WALL_CALL GetRule(const char* name,net_wall* wall_glob,net_wall_rule** out)noexcept(false){
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
		}
#endif
	}
#endif // WIN32
}