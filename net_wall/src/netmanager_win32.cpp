#include "netmanager.h"
#include <iostream>
namespace net_wall {
	struct net_list_manager_win32 :public net_list_manager {
		INetworkListManager* manager=NULL;
	};
	void NET_WALL_API NET_WALL_CALL InitializeNetListManager(net_list_manager** out) {
		net_list_manager_win32* mgr = new net_list_manager_win32;
		if (SUCCEEDED(CoCreateInstance(CLSID_NetworkListManager, NULL,
			CLSCTX_ALL, IID_INetworkListManager,
			(LPVOID*)&mgr->manager))) {
			out[0] = mgr;
			return;
		}
		delete mgr;
		throw permission_denied();
	}
	void NET_WALL_API NET_WALL_CALL Cleanup(net_list_manager* manager) {
		net_list_manager_win32* mgr = (net_list_manager_win32*)manager;
		if (mgr->manager != NULL) {
			mgr->manager->Release();
			delete mgr;
		}
	}
}