#Protocol="MODBUS"
#CreationDate="2018-11-20"
#Modbus Malicious Activity detection script by Jeff Barron (jeff.barron@criticalpathsecurity.com)


@load base/frameworks/files
@load base/frameworks/notice
@load base/protocols/modbus
@load base/protocols/modbus/consts
export {
redef enum Notice::Type +=
	{
    notice::ICS_ModBus_Diagnostics_Function,
    notice::ICS_ModBus_Firmware_Replacement_Function,
    notice::ICS_ModBus_Encapsulated_Interface_Transfer,
    notice::ICS_ModBus_Unknown_Function,
    notice::ICS_ModBus_Illegal_Address_Value

};

}
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
	{
	if ( ! c?$modbus )
		{
		c$modbus = [$ts=network_time(), $uid=c$uid, $id=c$id];
		}

	c$modbus$ts   = network_time();

	# for some reason when $identifier=cat(c$id$orig_h is in the notice call it doesn't send out notices 1:1 for events it sends out 1 notice for many events

#it is very unlikely that sensors, HMIs, PLCs and other devices in an ICS network are going to send a function that isn't understood.
#This detects when an attacker is trying to break things or try things that were not intended.
#A russian state actor might have an attack they used against a power plant that they are now running against an oil pipeline for example.

	 if (headers$function_code !in Modbus::function_codes)
	    {

	        NOTICE([$note=notice::ICS_ModBus_Unknown_Function,
					$sub=fmt("Stage 4: Exploitation"),
	        $msg=fmt("Unknown Modbus Function!"),
	        $conn=c]);
	    }


	 if (headers$function_code == 0x7e)
	    {
	     #print "Firmware_replacement alert";

	     NOTICE([$note=notice::ICS_ModBus_Firmware_Replacement_Function,
			 $msg=fmt("Modbus Firmware_replace function has been issued!"),
			 $sub=fmt("Stage 5: Installation"),
			 $conn=c]);
	    }

	 if (headers$function_code == 0x8)
	    {
	     #print "Modbus diagnostic message hit!";
#While this detection could alert for recon it's more likely that an attacker is trying to lock up, or stop a device from functioning properly by sending this function #code
	     NOTICE([$note=notice::ICS_ModBus_Diagnostics_Function,
			 $msg=fmt("Modbus Diagnostics function has been issued!"),
			 $sub=fmt("Stage 4: Exploitation"),
			 $conn=c]);
	    }

	#ModBus encapsulated interface allows other protocols to tunnel through modbus.  This could be part of delivery.
	#it could be used to circumvent access controls.
	     if (headers$function_code == 0x2B)
	    {

	     NOTICE([$note=notice::ICS_ModBus_Encapsulated_Interface_Transfer,
			 $msg=fmt(" Warning! Modbus encapsulated interface transfer received!"),
			 $sub=fmt("Stage 3: Delivery"),
			 $conn=c]);
	    }


    }


event modbus_exception(c: connection, headers: ModbusHeaders, code: count) &priority=5
	{

	#c$modbus$exception = Modbus::exception_codes[code];


	#Check for exception codes to detect illegal memory addresses indicating that attackers could be trying to cause undefinded or unsafe behavior
	#These illegal values should only occur if something is badly broken or if an attacker is actively trying to exploit or find bugs to exploit on the system
	#In an ICS environment this means things will break. Sensors will fail.  Things will start or stop moving.

	    if (code == 0x02 || code == 0x03)

            #0x2 ILLEGAL DATA ADDRESS  0x3 ILLEGAL DATA VALUE

            #these exceptions occur when a request is made to access memory outside of the valid modbus plc registers address range.
	    {


	     NOTICE([$note=notice::ICS_ModBus_Illegal_Address_Value,
			 $msg=fmt("Modbus Exception: Illegal Data Address and/or Illegal Data Value! A request for an illegal value or writing an illegal value could cause undefined and unsafe behavior."),
			 $sub=fmt("Stage 4: Exploitation"),
			 $conn=c]);
	    }


}
