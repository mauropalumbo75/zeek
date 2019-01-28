enum smb3_tree_connect_flags {
	SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT	= 0x0001,
	SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER	= 0x0002,
	SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT	= 0x0004,
};

enum smb3_tree_connect_context_type {
	SMB2_RESERVED_TREE_CONNECT_CONTEXT_ID		= 0x0000,
	SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID	= 0x0001,
};


refine connection SMB_Conn += {

	function proc_smb2_tree_connect_request(header: SMB2_Header, val: SMB2_tree_connect_request): bool
		%{
		if ( smb2_tree_connect_request )
			BifEvent::generate_smb2_tree_connect_request(bro_analyzer(),
			                                             bro_analyzer()->Conn(),
			                                             BuildSMB2HeaderVal(header),
			                                             smb2_string2stringval(${val.buffer.path})  //#TODO this is not ok for smb 3.1.1
									);

		return true;
		%}

	function proc_smb2_tree_connect_response(header: SMB2_Header, val: SMB2_tree_connect_response): bool
		%{
		if ( ${val.share_type} == SMB2_SHARE_TYPE_PIPE )
			set_tree_is_pipe(${header.tree_id});

		if ( smb2_tree_connect_response )
			{
			RecordVal* resp = new RecordVal(BifType::Record::SMB2::TreeConnectResponse);
			resp->Assign(0, val_mgr->GetCount(${val.share_type}));

			BifEvent::generate_smb2_tree_connect_response(bro_analyzer(),
			                                              bro_analyzer()->Conn(),
			                                              BuildSMB2HeaderVal(header),
			                                              resp);
			}

		return true;
		%}

};


type SMB3_remoted_identity_tree_connect_context = record {
	ticket_type 		: uint16;
	ticket_size		: uint16;
	user			: uint16;
	user_name		: uint16;
	domain			: uint16;
	groups			: uint16;
	restricted_groups	: uint16;
	privileges		: uint16;
	primary_group		: uint16;
	owner			: uint16;
	default_dacl		: uint16;
	device_groups		: uint16;
	user_claims		: uint16;
	device_claims		: uint16;
	ticket_info		: bytestring &length = ticket_size;  #TODO not so easy to extract data from inside
};

type SMB3_tree_connect_context = record {
	context_type	: uint32;
	data_length	: uint16;
	reserved	: padding[4];
	data		: case context_type of {   
		SMB2_RESERVED_TREE_CONNECT_CONTEXT_ID		-> reserved : empty;
		SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID	-> remoted_identity : SMB3_remoted_identity_tree_connect_context;	
	};
};

type SMB3_tree_connect_extension(tc : SMB2_tree_connect_request) = record {
	tc_context_offset 	: uint32;
	tc_context_count	: uint16;
	reserved		: padding[10];
	path_name		: SMB2_string(tc.path_length);
	data			: SMB3_tree_connect_context[tc_context_count];
};

type SMB2_extension(tc : SMB2_tree_connect_request) = case tc.flags of {   
	SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT   -> smb3_tree_connect_extension       : SMB3_tree_connect_extension(tc);	
	default					   -> path           			: SMB2_string(tc.path_length); 
												# if no smb3 flag is present, this is the path		
	};

type SMB2_tree_connect_request(header: SMB2_Header) = record {
	structure_size 	: uint16;
	flags          	: uint16;
	path_offset    	: uint16;
	path_length    	: uint16;
	pad            	: padding to path_offset - header.head_length;
	buffer		: SMB2_extension(this);
} &let {
	proc: bool = $context.connection.proc_smb2_tree_connect_request(header, this);
};

type SMB2_tree_connect_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	share_type        : uint8;
	reserved          : padding[1];
	share_flags       : uint32;
	capabilities      : uint32;
	maximal_access    : uint32;
} &let {
	proc: bool = $context.connection.proc_smb2_tree_connect_response(header, this);
};

