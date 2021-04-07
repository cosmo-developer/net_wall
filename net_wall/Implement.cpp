#include "net_wall.h"
#include <iostream>
namespace net_wall{
#if WIN32
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
	extern "C" {

		void NET_WALL_API NET_WALL_CALL  Initialize(net_wall* wall,FWProfile profile) {
			HRESULT hr = S_OK;
			wall->profile = profile;
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
		void NET_WALL_API NET_WALL_CALL Cleanup(net_wall* wall) {
			if (wall->pNetFwPolicy2 != NULL) {
				wall->pNetFwPolicy2->Release();
				wall->pNetFwPolicy2 = NULL;
			}
			if (SUCCEEDED(wall->hrComInit)) {
				wall->hrComInit = S_FALSE;
				CoUninitialize();
			}
		}

		bool NET_WALL_API NET_WALL_CALL IsEnabled(net_wall* wall) {
			VARIANT_BOOL enabled = 0;
			if (SUCCEEDED(wall->pNetFwPolicy2->get_FirewallEnabled(NETFWPROFILETYPE2FromFWProfile(wall->profile), &enabled))) {
				return (enabled == -1) ? true : false;
			}
			return false;
		}

		void NET_WALL_API NET_WALL_CALL SetEnabled(net_wall* wall, bool enabled) {
			VARIANT_BOOL en = (enabled == true) ? -1 : 0;
			if (SUCCEEDED(wall->pNetFwPolicy2->put_FirewallEnabled(NETFWPROFILETYPE2FromFWProfile(wall->profile), en))) {
				return;
			}
		}
#if WIN32 
		bool NET_WALL_API NET_WALL_CALL IsBlockAllInboundTraffic(net_wall* wall) {
			VARIANT_BOOL enabled;
			if (SUCCEEDED(wall->pNetFwPolicy2->get_BlockAllInboundTraffic(NETFWPROFILETYPE2FromFWProfile(wall->profile), &enabled))) {
				return (enabled == -1) ? true : false;
			}
			return false;
		}
		void NET_WALL_API NET_WALL_CALL SetBlockAllInboundTraffic(net_wall* wall, bool enabled) {
			if (SUCCEEDED(wall->pNetFwPolicy2->put_BlockAllInboundTraffic(NETFWPROFILETYPE2FromFWProfile(wall->profile), (enabled == true) ? -1 : 0))) {
				return;
			}
		}
#endif
	}
#endif // WIN32
}