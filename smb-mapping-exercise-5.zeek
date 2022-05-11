@load base/frameworks/notice

module SMB_ADMIN_MAPPING;

export {
	const admin_shares: pattern =
		/ADMIN\$/
	|	/ADMINISTRATOR\$/
	|	/PRINT\$/
#	|	/IPC\$/
	|	/ROOT\$/
	|	/C\$/
	|	/D\$/
	|	/E\$/
	|	/F\$/
	|	/DEV\$/
	|	/SYS\$/
	|	/FAX\$/
	|	/SYSVOL/
	|	/NETLOGON/
	&redef;
}

export {
	redef enum Notice::Type += {
		SMB_ADMIN_MAPPING
	};
}

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
{
	if (SMB_ADMIN_MAPPING::admin_shares in to_upper(path))
	{
		NOTICE([$note=SMB_ADMIN_MAPPING,
			$conn=c,
			$msg=fmt("SMB: %s mapped administrative share: %s, from %s", c$id$orig_h, path, c$id$resp_h),
			$identifier=cat(c$id$resp_h),
			$sub=fmt("Severity: 4"),
			$suppress_for=5min]);
	}
}

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, service: string, native_file_system: string)
{
	if (SMB_ADMIN_MAPPING::admin_shares in to_upper(service))
	{
		NOTICE([$note=SMB_ADMIN_MAPPING,
			$conn=c,
			$msg=fmt("SMB: %s mapped administrative share: %s, from %s", c$id$orig_h, service, c$id$resp_h),
			$identifier=cat(c$id$resp_h),
			$sub=fmt("Severity: 4"),
			$suppress_for=5min]);
	}
}
