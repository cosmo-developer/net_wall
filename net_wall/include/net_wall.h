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
#include <netlistmgr.h>
#pragma comment(lib,"ole32.lib")
#endif
#define PERMISSION_ERROR_MSG "Admin permission not guranted/ Run In Admin mode"
namespace net_wall{
	enum class FWProfile {
		__DOMAIN=0b001, __PUBLIC=0b010, __PRIVATE=0b100,__ALL=0b111
	};
	enum class FWAction {
		FWA_BLOCK,FWA_ALLOW,FWA_MAX
	};
	enum class Bound {
		B_INBOUND=0b01,B_OUTBOUND=0b10,B_MAX=0b11
	};
	enum class Protocol {
		TCP,UDP,ANY
	};
	struct net_wall {};//implementation provided by platform
	struct net_wall_rule {};//implementation provided by platform
	struct net_wall_service_restriction {}; //implementation provided by win32 platform INetFwServiceRestriction
	struct net_wall_service {}; //implementation provided by platform

	class permission_denied {
	public:
		char* what;
		permission_denied(const char* what = "Admin permission not guranted/ Run In Admin mode") :what((char*)what) {}
	};

	extern "C++" {
		bool NET_WALL_API NET_WALL_CALL Init();
		void NET_WALL_API NET_WALL_CALL Free();

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
		void NET_WALL_API NET_WALL_CALL AddRule(net_wall*, net_wall_rule*)noexcept(false);
		
		void NET_WALL_API NET_WALL_CALL RemoveRule(net_wall*, const char*)noexcept(false);
		void NET_WALL_API NET_WALL_CALL EnableGroupedRule(const char*, net_wall*, bool)noexcept(false);
		
		bool NET_WALL_API NET_WALL_CALL IsGroupEnabled(net_wall*, const char*);
		bool NET_WALL_API NET_WALL_CALL IsNotificationDisabled(net_wall*);
		
		void NET_WALL_API NET_WALL_CALL SetNotificationDisabled(net_wall*, bool)noexcept(false);
		bool NET_WALL_API NET_WALL_CALL IsUnicastResponsesToMulticastBroadcastDisabled(net_wall*);
		
		void NET_WALL_API NET_WALL_CALL SetUnicastResponsesToMulticastBroadcastDisabled(net_wall*,bool)noexcept(false);
		void NET_WALL_API NET_WALL_CALL RestoreDefaultSettings(net_wall*)noexcept(false);
		/** Rule Based Method********/
		void NET_WALL_API NET_WALL_CALL InitializeRule(net_wall_rule**)noexcept(false);
		
		void NET_WALL_API NET_WALL_CALL Cleanup(net_wall_rule*);
		
		void NET_WALL_API NET_WALL_CALL GroupOfRule(net_wall_rule*,char**);
		
		void NET_WALL_API NET_WALL_CALL GetName(net_wall_rule*, char**);
		void NET_WALL_API NET_WALL_CALL SetName(net_wall_rule*,const char*)noexcept(false);
		
		void NET_WALL_API NET_WALL_CALL GetDescription(net_wall_rule*, char**);
		void NET_WALL_API NET_WALL_CALL SetDescription(net_wall_rule*,const char*)noexcept(false);
		
		void NET_WALL_API NET_WALL_CALL GetApplicationName(net_wall_rule*, char**);
		void NET_WALL_API NET_WALL_CALL SetApplicationName(net_wall_rule*, const char*)noexcept(false);

		void NET_WALL_API NET_WALL_CALL GetServiceName(net_wall_rule*, char**);
		void NET_WALL_API NET_WALL_CALL SetServiceName(net_wall_rule*, const char*)noexcept(false);

		Protocol NET_WALL_API NET_WALL_CALL GetProtocol(net_wall_rule*);
		void NET_WALL_API NET_WALL_CALL SetProtocol(net_wall_rule*, Protocol)noexcept(false);

		Bound NET_WALL_API NET_WALL_CALL GetBound(net_wall_rule*);
		void NET_WALL_API NET_WALL_CALL SetBound(net_wall_rule*, Bound)noexcept(false);

#endif
	}
}