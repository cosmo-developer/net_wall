#pragma once
#if WIN32
#define NET_WALL_CALL __stdcall
#ifdef NET_WALL_BUILD_MODE
#define NET_WALL_API __declspec(dllexport)
#else
#define NET_WALL_API __declspec(dllimport)
#pragma comment(lib,"net_wall.lib")
#endif
#include <Windows.h>
#include <netfw.h>
#pragma comment(lib,"ole32.lib")
#endif
#define PERMISSION_ERROR_MSG "Admin permission not guranted/ Run In Admin mode"
namespace net_wall{
	enum FWProfile {
		__DOMAIN, __PUBLIC, __PRIVATE,__ALL
	};
	enum FWAction {
		BLOCK,ALLOW,MAX
	};
	struct net_wall {};//implementation provided by platform
	struct net_wall_rule {};//implementation provided by platform

	class permission_denied {
	public:
		char* what;
		permission_denied(const char* what = "Admin permission not guranted/ Run In Admin mode") :what((char*)what) {}
	};

	extern "C++" {
		void NET_WALL_API NET_WALL_CALL  Initialize(net_wall**,FWProfile);
		void NET_WALL_API NET_WALL_CALL Cleanup(net_wall*);
		bool NET_WALL_API NET_WALL_CALL IsEnabled(net_wall*);
		void NET_WALL_API NET_WALL_CALL SetEnabled(net_wall*, bool)noexcept(false);
		FWProfile NET_WALL_API NET_WALL_CALL GetProfile(net_wall*);

#if WIN32 
		bool NET_WALL_API NET_WALL_CALL IsBlockAllInboundTraffic(net_wall*);
		void NET_WALL_API NET_WALL_CALL SetBlockAllInboundTraffic(net_wall*, bool)noexcept(false);
		FWAction NET_WALL_API NET_WALL_CALL GetDefaultInboundAction(net_wall*);
		void NET_WALL_API NET_WALL_CALL SetDefaultInboundAction(net_wall*, FWAction)noexcept(false);
		FWAction NET_WALL_API NET_WALL_CALL GetDefaultOutboundAction(net_wall*);
		void NET_WALL_API NET_WALL_CALL SetDefaultOutboundAction(net_wall*, FWAction)noexcept(false);
		void NET_WALL_API NET_WALL_CALL GetRule(const char* name,net_wall*,net_wall_rule** out)noexcept(false);
		/** Rule Based Method********/
		void NET_WALL_API NET_WALL_CALL InitializeRule(net_wall_rule**)noexcept(false);
		void NET_WALL_API NET_WALL_CALL Cleanup(net_wall_rule* rl);
#endif
	}
}