enum smb3_capabilities {
	SMB2_GLOBAL_CAP_DFS			= 0,
	SMB2_GLOBAL_CAP_LEASING 		= 2,
	SMB2_GLOBAL_CAP_LARGE_MTU 		= 4,
	SMB2_GLOBAL_CAP_MULTI_CHANNEL   	= 8,
	SMB2_GLOBAL_CAP_PERSISTENT_HANDLES    	= 10,
	SMB2_GLOBAL_CAP_DIRECTORY_LEASING       = 20,
	SMB2_GLOBAL_CAP_ENCRYPTION              = 40,
};

enum smb3_context_type {
	SMB2_PREAUTH_INTEGRITY_CAPABILITIES	= 0x0001,
	SMB2_ENCRYPTION_CAPABILITIES 		= 0x0002,
};


refine connection SMB_Conn += {

	function proc_smb2_negotiate_request(h: SMB2_Header, val: SMB2_negotiate_request) : bool
		%{
		if ( smb2_negotiate_request )
			{
			VectorVal* dialects = new VectorVal(index_vec);
			for ( unsigned int i = 0; i < ${val.dialects}->size(); ++i )
				{
				dialects->Assign(i, val_mgr->GetCount((*${val.dialects})[i]));
				}
			BifEvent::generate_smb2_negotiate_request(bro_analyzer(), bro_analyzer()->Conn(),
			                                          BuildSMB2HeaderVal(h),
			                                          dialects);
			}

		return true;
		%}

	function proc_smb2_negotiate_response(h: SMB2_Header, val: SMB2_negotiate_response) : bool
		%{
		if ( smb2_negotiate_response )
			{
			RecordVal* nr = new RecordVal(BifType::Record::SMB2::NegotiateResponse);

			nr->Assign(0, val_mgr->GetCount(${val.dialect_revision}));
			nr->Assign(1, val_mgr->GetCount(${val.security_mode}));
			nr->Assign(2, BuildSMB2GUID(${val.server_guid})),
			nr->Assign(3, filetime2brotime(${val.system_time}));
			nr->Assign(4, filetime2brotime(${val.server_start_time}));
			BifEvent::generate_smb2_negotiate_response(bro_analyzer(), bro_analyzer()->Conn(),
			                                           BuildSMB2HeaderVal(h),
			                                           nr);
			}

		return true;
		%}
};

type SMB3_preauth_integrity_capabilities = record {
	hash_alg_count    	: uint16;          
	salt_lenght     	: uint16;          
	hash_alg		: uint16[hash_alg_count];	   
	salt			: bytestring &length = salt_lenght;   #TODO is a bytestring ok for this field?
};

type SMB3_encryption_capabilities = record {
	cipher_count    	: uint16;                  
	ciphers			: uint16[cipher_count];	   
};

type SMB3_negotiate_context_values = record {
	context_type    	: uint16;          # specify the type of context
	data_lenght     	: uint16;          # the lenght of the data field
	reserved		: uint32;	   # ignored
	data			: case context_type of {   
		SMB2_PREAUTH_INTEGRITY_CAPABILITIES    	-> preauth_integrity_capabilities          : SMB3_preauth_integrity_capabilities;	
		SMB2_ENCRYPTION_CAPABILITIES		-> encryption_capabilities	    	   : SMB3_encryption_capabilities;			
	};
};

type SMB3_negotiate_context_extra = record {
	negotiate_context_offset    	: uint16;          # the offset in bytes from the beginning of the header to the first negotiate context 
	negotiate_context_count     	: uint8;           # the number of negotiate contexts
	reserved			: uint8;	   # ignored
};

type SMB3_negotiate_context_info(nr: SMB2_negotiate_request) = case nr.dialects[nr.dialect_count-1] of {   # check the last dialect #TODO is this ok?
	0x0311    	-> negotiate_context_extra          : SMB3_negotiate_context_extra;	# if it is v. 3.1.1
	default		-> client_start_time 		    : SMB_timestamp;			# any other version 
};

type SMB3_negotiate_context_list(nr: SMB2_negotiate_request) = case nr.dialects[nr.dialect_count-1] of {   # check the last dialect #TODO is this ok?
	0x0311    	-> negotiate_context_list: SMB3_negotiate_context_values[nr.negotiate_context_info.negotiate_context_extra.negotiate_context_count];	# if it is v. 3.1.1
	default		-> unknown : empty;			# any other version 
};

type SMB3_negotiate_context_list2(nr: SMB2_negotiate_response) = case nr.dialect_revision of {   # check the dialect
	0x0311    	-> negotiate_context_list: SMB3_negotiate_context_values[nr.negotiate_context_count];	# if it is v. 3.1.1
	default		-> unknown : empty;			# any other version 
};

type SMB2_negotiate_request(header: SMB2_Header) = record {
	structure_size    	: uint16;          # client MUST set this to 36
	dialect_count     	: uint16;          # must be > 0
	security_mode     	: uint16;          # there is a list of required modes
	reserved          	: padding[2];      # must be set to 0
	capabilities      	: uint32;          # must be set to 0 if SMB 2.x, otherwise if SMB 3.x one of enum smb2_capabilities
	client_guid       	: SMB2_guid;       # guid if client implements SMB 2.1 dialect, otherwise set to 0
	negotiate_context_info  : SMB3_negotiate_context_info(this);  
	dialects          	: uint16[dialect_count];	 # array of SMB accepted dialects 
	pad			: padding align 8; # TODO padding is different from first case and others?
	negotiate_context_list  : SMB3_negotiate_context_list(this);	
} &byteorder=littleendian, &let {
	proc : bool = $context.connection.proc_smb2_negotiate_request(header, this);
};

type SMB2_negotiate_response(header: SMB2_Header) = record {
	structure_size    		: uint16;
	security_mode     		: uint16;
	dialect_revision  		: uint16;
	negotiate_context_count  	: uint16;	# reserved to 0 if not smb 3.1.1
	server_guid       		: SMB2_guid;
	capabilities      		: uint32;
	max_transact_size 		: uint32;
	max_read_size     		: uint32;
	max_write_size    		: uint32;
	system_time       		: SMB_timestamp;
	server_start_time 		: SMB_timestamp;
	security_offset   		: uint16;
	security_length   		: uint16;
	negotiate_context_offset	: uint32;
	pad1              		: padding to security_offset - header.head_length;
	security_blob     		: bytestring &length=security_length;
	pad2				: padding align 8; 	# optional padding
	negotiate_context_list  	: SMB3_negotiate_context_list2(this);	
} &byteorder=littleendian, &let {
	proc : bool = $context.connection.proc_smb2_negotiate_response(header, this);
	gssapi_proc : bool = $context.connection.forward_gssapi(security_blob, false);

};
