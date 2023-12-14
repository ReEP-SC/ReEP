/*
 * @source: etherscan.io 
 * @author: -
 * @vulnerable_at_lines: 63
 */

pragma solidity ^0.4.19;

contract PENNY_BY_PENNY  
{
    struct Holder   
    {
        uint unlockTime;
        uint balance;
    }
    
    mapping (address => Holder) public Acc;
    
    uint public MinSum;
    
    LogFile Log;
    
    bool intitalized;
    
    function SetMinSum(uint _val)
    public
    {
        if(intitalized)throw;
        MinSum = _val;
    }
    
    function SetLogFile(address _log)
    public
    {
        if(intitalized)throw;
        Log = LogFile(_log);
    }
    
    function Initialized()
    public
    {
        intitalized = true;
    }
    
    function Put(uint _lockTime)
    public
    payable
    {
        // Log.AddMessage(msg.sender,msg.value,"Put");
        var acc = Acc[msg.sender];
        acc.balance += msg.value;
        if(now+_lockTime>acc.unlockTime)
            acc.unlockTime=now+_lockTime;
            Log.AddMessage(msg.sender,msg.value,"Put");

    }
    
    function Collect(uint _am)
    public
    payable
    {
        // Log.AddMessage(msg.sender,_am,"Collect");
        var acc = Acc[msg.sender];
        // if( acc.balance>=MinSum && acc.balance>=_am && now>acc.unlockTime)
        if( acc.balance>=MinSum && acc.balance>=_am)
        {
            // <yes> <report> REENTRANCY
            if(msg.sender.call.value(_am)())
            {
                acc.balance-=_am;
                Log.AddMessage(msg.sender,_am,"Collect");
            }
        }
    }
    
    function() 
    public 
    payable
    {
        Put(0);
    }
    
}


contract LogFile
{
    struct Message
    {
        address Sender;
        string  Data;
        uint Val;
        uint  Time;
    }
    
    Message[] public History;
    
    Message LastMsg;
    
    function AddMessage(address _adr,uint _val,string _data)
    public
    {
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
    }
}




// label_0000:
// 	// Inputs[1] { @0005  msg.value }
// 	0000    60  PUSH1 0x80
// 	0002    60  PUSH1 0x40
// 	0004    52  MSTORE
// 	0005    34  CALLVALUE
// 	0006    80  DUP1
// 	0007    15  ISZERO
// 	0008    61  PUSH2 0x0010
// 	000B    57  *JUMPI
// 	// Stack delta = +1
// 	// Outputs[2]
// 	// {
// 	//     @0004  memory[0x40:0x60] = 0x80
// 	//     @0005  stack[0] = msg.value
// 	// }
// 	// Block ends with conditional jump to 0x0010, if !msg.value

// label_000C:
// 	// Incoming jump from 0x000B, if not !msg.value
// 	// Inputs[1] { @000F  memory[0x00:0x00] }
// 	000C    60  PUSH1 0x00
// 	000E    80  DUP1
// 	000F    FD  *REVERT
// 	// Stack delta = +0
// 	// Outputs[1] { @000F  revert(memory[0x00:0x00]); }
// 	// Block terminates

// label_0010:
// 	// Incoming jump from 0x000B, if !msg.value
// 	// Inputs[1] { @001E  memory[0x00:0x061c] }
// 	0010    5B  JUMPDEST
// 	0011    50  POP
// 	0012    61  PUSH2 0x061c
// 	0015    80  DUP1
// 	0016    61  PUSH2 0x0020
// 	0019    60  PUSH1 0x00
// 	001B    39  CODECOPY
// 	001C    60  PUSH1 0x00
// 	001E    F3  *RETURN
// 	// Stack delta = -1
// 	// Outputs[2]
// 	// {
// 	//     @001B  memory[0x00:0x061c] = code[0x20:0x063c]
// 	//     @001E  return memory[0x00:0x061c];
// 	// }
// 	// Block terminates

// 	001F    00    *STOP
// 	0020    60    PUSH1 0x80
// 	0022    60    PUSH1 0x40
// 	0024    52    MSTORE
// 	0025    60    PUSH1 0x04
// 	0027    36    CALLDATASIZE
// 	0028    10    LT
// 	0029    61    PUSH2 0x0083
// 	002C    57    *JUMPI
// 	002D    60    PUSH1 0x00
// 	002F    35    CALLDATALOAD
// 	0030    7C    PUSH29 0x0100000000000000000000000000000000000000000000000000000000
// 	004E    90    SWAP1
// 	004F    04    DIV
// 	0050    63    PUSH4 0xffffffff
// 	0055    16    AND
// 	0056    80    DUP1
// 	0057    63    PUSH4 0x303b9379
// 	005C    14    EQ
// 	005D    61    PUSH2 0x008f
// 	0060    57    *JUMPI
// 	0061    80    DUP1
// 	0062    63    PUSH4 0x3fe43822
// 	0067    14    EQ
// 	0068    61    PUSH2 0x00d2
// 	006B    57    *JUMPI
// 	006C    80    DUP1
// 	006D    63    PUSH4 0x5daa87a0
// 	0072    14    EQ
// 	0073    61    PUSH2 0x00f2
// 	0076    57    *JUMPI
// 	0077    80    DUP1
// 	0078    63    PUSH4 0x640d3017
// 	007D    14    EQ
// 	007E    61    PUSH2 0x0109
// 	0081    57    *JUMPI
// 	0082    80    DUP1
// 	0083    63    PUSH4 0x65f3c31a
// 	0088    14    EQ
// 	0089    61    PUSH2 0x0136
// 	008C    57    *JUMPI
// 	008D    80    DUP1
// 	008E    63    PUSH4 0x7731cd2a
// 	0093    14    EQ
// 	0094    61    PUSH2 0x0156
// 	0097    57    *JUMPI
// 	0098    80    DUP1
// 	0099    63    PUSH4 0xc2808d1a
// 	009E    14    EQ
// 	009F    61    PUSH2 0x01b4
// 	00A2    57    *JUMPI
// 	00A3    5B    JUMPDEST
// 	00A4    61    PUSH2 0x008d
// 	00A7    60    PUSH1 0x00
// 	00A9    61    PUSH2 0x01df
// 	00AC    56    *JUMP
// 	00AD    5B    JUMPDEST
// 	00AE    00    *STOP
// 	00AF    5B    JUMPDEST
// 	00B0    34    CALLVALUE
// 	00B1    80    DUP1
// 	00B2    15    ISZERO
// 	00B3    61    PUSH2 0x009b
// 	00B6    57    *JUMPI
// 	00B7    60    PUSH1 0x00
// 	00B9    80    DUP1
// 	00BA    FD    *REVERT
// 	00BB    5B    JUMPDEST
// 	00BC    50    POP
// 	00BD    61    PUSH2 0x00d0
// 	00C0    60    PUSH1 0x04
// 	00C2    80    DUP1
// 	00C3    36    CALLDATASIZE
// 	00C4    03    SUB
// 	00C5    81    DUP2
// 	00C6    01    ADD
// 	00C7    90    SWAP1
// 	00C8    80    DUP1
// 	00C9    80    DUP1
// 	00CA    35    CALLDATALOAD
// 	00CB    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	00E0    16    AND
// 	00E1    90    SWAP1
// 	00E2    60    PUSH1 0x20
// 	00E4    01    ADD
// 	00E5    90    SWAP1
// 	00E6    92    SWAP3
// 	00E7    91    SWAP2
// 	00E8    90    SWAP1
// 	00E9    50    POP
// 	00EA    50    POP
// 	00EB    50    POP
// 	00EC    61    PUSH2 0x0367
// 	00EF    56    *JUMP
// 	00F0    5B    JUMPDEST
// 	00F1    00    *STOP
// 	00F2    5B    JUMPDEST
// 	00F3    61    PUSH2 0x00f0
// 	00F6    60    PUSH1 0x04
// 	00F8    80    DUP1
// 	00F9    36    CALLDATASIZE
// 	00FA    03    SUB
// 	00FB    81    DUP2
// 	00FC    01    ADD
// 	00FD    90    SWAP1
// 	00FE    80    DUP1
// 	00FF    80    DUP1
// 	0100    35    CALLDATALOAD
// 	0101    90    SWAP1
// 	0102    60    PUSH1 0x20
// 	0104    01    ADD
// 	0105    90    SWAP1
// 	0106    92    SWAP3
// 	0107    91    SWAP2
// 	0108    90    SWAP1
// 	0109    50    POP
// 	010A    50    POP
// 	010B    50    POP
// 	010C    61    PUSH2 0x03c5
// 	010F    56    *JUMP
// 	0110    5B    JUMPDEST
// 	0111    00    *STOP
// 	0112    5B    JUMPDEST
// 	0113    34    CALLVALUE
// 	0114    80    DUP1
// 	0115    15    ISZERO
// 	0116    61    PUSH2 0x00fe
// 	0119    57    *JUMPI
// 	011A    60    PUSH1 0x00
// 	011C    80    DUP1
// 	011D    FD    *REVERT
// 	011E    5B    JUMPDEST
// 	011F    50    POP
// 	0120    61    PUSH2 0x0107
// 	0123    61    PUSH2 0x0585
// 	0126    56    *JUMP
// 	0127    5B    JUMPDEST
// 	0128    00    *STOP
// 	0129    5B    JUMPDEST
// 	012A    34    CALLVALUE
// 	012B    80    DUP1
// 	012C    15    ISZERO
// 	012D    61    PUSH2 0x0115
// 	0130    57    *JUMPI
// 	0131    60    PUSH1 0x00
// 	0133    80    DUP1
// 	0134    FD    *REVERT
// 	0135    5B    JUMPDEST
// 	0136    50    POP
// 	0137    61    PUSH2 0x0134
// 	013A    60    PUSH1 0x04
// 	013C    80    DUP1
// 	013D    36    CALLDATASIZE
// 	013E    03    SUB
// 	013F    81    DUP2
// 	0140    01    ADD
// 	0141    90    SWAP1
// 	0142    80    DUP1
// 	0143    80    DUP1
// 	0144    35    CALLDATALOAD
// 	0145    90    SWAP1
// 	0146    60    PUSH1 0x20
// 	0148    01    ADD
// 	0149    90    SWAP1
// 	014A    92    SWAP3
// 	014B    91    SWAP2
// 	014C    90    SWAP1
// 	014D    50    POP
// 	014E    50    POP
// 	014F    50    POP
// 	0150    61    PUSH2 0x05a2
// 	0153    56    *JUMP
// 	0154    5B    JUMPDEST
// 	0155    00    *STOP
// 	0156    5B    JUMPDEST
// 	0157    61    PUSH2 0x0154
// 	015A    60    PUSH1 0x04
// 	015C    80    DUP1
// 	015D    36    CALLDATASIZE
// 	015E    03    SUB
// 	015F    81    DUP2
// 	0160    01    ADD
// 	0161    90    SWAP1
// 	0162    80    DUP1
// 	0163    80    DUP1
// 	0164    35    CALLDATALOAD
// 	0165    90    SWAP1
// 	0166    60    PUSH1 0x20
// 	0168    01    ADD
// 	0169    90    SWAP1
// 	016A    92    SWAP3
// 	016B    91    SWAP2
// 	016C    90    SWAP1
// 	016D    50    POP
// 	016E    50    POP
// 	016F    50    POP
// 	0170    61    PUSH2 0x01df
// 	0173    56    *JUMP
// 	0174    5B    JUMPDEST
// 	0175    00    *STOP
// 	0176    5B    JUMPDEST
// 	0177    34    CALLVALUE
// 	0178    80    DUP1
// 	0179    15    ISZERO
// 	017A    61    PUSH2 0x0162
// 	017D    57    *JUMPI
// 	017E    60    PUSH1 0x00
// 	0180    80    DUP1
// 	0181    FD    *REVERT
// 	0182    5B    JUMPDEST
// 	0183    50    POP
// 	0184    61    PUSH2 0x0197
// 	0187    60    PUSH1 0x04
// 	0189    80    DUP1
// 	018A    36    CALLDATASIZE
// 	018B    03    SUB
// 	018C    81    DUP2
// 	018D    01    ADD
// 	018E    90    SWAP1
// 	018F    80    DUP1
// 	0190    80    DUP1
// 	0191    35    CALLDATALOAD
// 	0192    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	01A7    16    AND
// 	01A8    90    SWAP1
// 	01A9    60    PUSH1 0x20
// 	01AB    01    ADD
// 	01AC    90    SWAP1
// 	01AD    92    SWAP3
// 	01AE    91    SWAP2
// 	01AF    90    SWAP1
// 	01B0    50    POP
// 	01B1    50    POP
// 	01B2    50    POP
// 	01B3    61    PUSH2 0x05c6
// 	01B6    56    *JUMP
// 	01B7    5B    JUMPDEST
// 	01B8    60    PUSH1 0x40
// 	01BA    51    MLOAD
// 	01BB    80    DUP1
// 	01BC    83    DUP4
// 	01BD    81    DUP2
// 	01BE    52    MSTORE
// 	01BF    60    PUSH1 0x20
// 	01C1    01    ADD
// 	01C2    82    DUP3
// 	01C3    81    DUP2
// 	01C4    52    MSTORE
// 	01C5    60    PUSH1 0x20
// 	01C7    01    ADD
// 	01C8    92    SWAP3
// 	01C9    50    POP
// 	01CA    50    POP
// 	01CB    50    POP
// 	01CC    60    PUSH1 0x40
// 	01CE    51    MLOAD
// 	01CF    80    DUP1
// 	01D0    91    SWAP2
// 	01D1    03    SUB
// 	01D2    90    SWAP1
// 	01D3    F3    *RETURN
// 	01D4    5B    JUMPDEST
// 	01D5    34    CALLVALUE
// 	01D6    80    DUP1
// 	01D7    15    ISZERO
// 	01D8    61    PUSH2 0x01c0
// 	01DB    57    *JUMPI
// 	01DC    60    PUSH1 0x00
// 	01DE    80    DUP1
// 	01DF    FD    *REVERT
// 	01E0    5B    JUMPDEST
// 	01E1    50    POP
// 	01E2    61    PUSH2 0x01c9
// 	01E5    61    PUSH2 0x05ea
// 	01E8    56    *JUMP
// 	01E9    5B    JUMPDEST
// 	01EA    60    PUSH1 0x40
// 	01EC    51    MLOAD
// 	01ED    80    DUP1
// 	01EE    82    DUP3
// 	01EF    81    DUP2
// 	01F0    52    MSTORE
// 	01F1    60    PUSH1 0x20
// 	01F3    01    ADD
// 	01F4    91    SWAP2
// 	01F5    50    POP
// 	01F6    50    POP
// 	01F7    60    PUSH1 0x40
// 	01F9    51    MLOAD
// 	01FA    80    DUP1
// 	01FB    91    SWAP2
// 	01FC    03    SUB
// 	01FD    90    SWAP1
// 	01FE    F3    *RETURN
// 	01FF    5B    JUMPDEST
// 	0200    60    PUSH1 0x00
// 	0202    80    DUP1
// 	0203    60    PUSH1 0x00
// 	0205    33    CALLER
// 	0206    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	021B    16    AND
// 	021C    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	0231    16    AND
// 	0232    81    DUP2
// 	0233    52    MSTORE
// 	0234    60    PUSH1 0x20
// 	0236    01    ADD
// 	0237    90    SWAP1
// 	0238    81    DUP2
// 	0239    52    MSTORE
// 	023A    60    PUSH1 0x20
// 	023C    01    ADD
// 	023D    60    PUSH1 0x00
// 	023F    20    SHA3
// 	0240    90    SWAP1
// 	0241    50    POP
// 	0242    34    CALLVALUE
// 	0243    81    DUP2
// 	0244    60    PUSH1 0x01
// 	0246    01    ADD
// 	0247    60    PUSH1 0x00
// 	0249    82    DUP3
// 	024A    82    DUP3
// 	024B    54    SLOAD
// 	024C    01    ADD
// 	024D    92    SWAP3
// 	024E    50    POP
// 	024F    50    POP
// 	0250    81    DUP2
// 	0251    90    SWAP1
// 	0252    55    SSTORE
// 	0253    50    POP
// 	0254    80    DUP1
// 	0255    60    PUSH1 0x00
// 	0257    01    ADD
// 	0258    54    SLOAD
// 	0259    82    DUP3
// 	025A    42    TIMESTAMP
// 	025B    01    ADD
// 	025C    11    GT
// 	025D    15    ISZERO
// 	025E    61    PUSH2 0x024d
// 	0261    57    *JUMPI
// 	0262    81    DUP2
// 	0263    42    TIMESTAMP
// 	0264    01    ADD
// 	0265    81    DUP2
// 	0266    60    PUSH1 0x00
// 	0268    01    ADD
// 	0269    81    DUP2
// 	026A    90    SWAP1
// 	026B    55    SSTORE
// 	026C    50    POP
// 	026D    5B    JUMPDEST
// 	026E    60    PUSH1 0x02
// 	0270    60    PUSH1 0x00
// 	0272    90    SWAP1
// 	0273    54    SLOAD
// 	0274    90    SWAP1
// 	0275    61    PUSH2 0x0100
// 	0278    0A    EXP
// 	0279    90    SWAP1
// 	027A    04    DIV
// 	027B    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	0290    16    AND
// 	0291    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	02A6    16    AND
// 	02A7    63    PUSH4 0x4c2f04a4
// 	02AC    33    CALLER
// 	02AD    34    CALLVALUE
// 	02AE    60    PUSH1 0x40
// 	02B0    51    MLOAD
// 	02B1    83    DUP4
// 	02B2    63    PUSH4 0xffffffff
// 	02B7    16    AND
// 	02B8    7C    PUSH29 0x0100000000000000000000000000000000000000000000000000000000
// 	02D6    02    MUL
// 	02D7    81    DUP2
// 	02D8    52    MSTORE
// 	02D9    60    PUSH1 0x04
// 	02DB    01    ADD
// 	02DC    80    DUP1
// 	02DD    83    DUP4
// 	02DE    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	02F3    16    AND
// 	02F4    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	0309    16    AND
// 	030A    81    DUP2
// 	030B    52    MSTORE
// 	030C    60    PUSH1 0x20
// 	030E    01    ADD
// 	030F    82    DUP3
// 	0310    81    DUP2
// 	0311    52    MSTORE
// 	0312    60    PUSH1 0x20
// 	0314    01    ADD
// 	0315    80    DUP1
// 	0316    60    PUSH1 0x20
// 	0318    01    ADD
// 	0319    82    DUP3
// 	031A    81    DUP2
// 	031B    03    SUB
// 	031C    82    DUP3
// 	031D    52    MSTORE
// 	031E    60    PUSH1 0x03
// 	0320    81    DUP2
// 	0321    52    MSTORE
// 	0322    60    PUSH1 0x20
// 	0324    01    ADD
// 	0325    80    DUP1
// 	0326    7F    PUSH32 0x5075740000000000000000000000000000000000000000000000000000000000
// 	0347    81    DUP2
// 	0348    52    MSTORE
// 	0349    50    POP
// 	034A    60    PUSH1 0x20
// 	034C    01    ADD
// 	034D    93    SWAP4
// 	034E    50    POP
// 	034F    50    POP
// 	0350    50    POP
// 	0351    50    POP
// 	0352    60    PUSH1 0x00
// 	0354    60    PUSH1 0x40
// 	0356    51    MLOAD
// 	0357    80    DUP1
// 	0358    83    DUP4
// 	0359    03    SUB
// 	035A    81    DUP2
// 	035B    60    PUSH1 0x00
// 	035D    87    DUP8
// 	035E    80    DUP1
// 	035F    3B    EXTCODESIZE
// 	0360    15    ISZERO
// 	0361    80    DUP1
// 	0362    15    ISZERO
// 	0363    61    PUSH2 0x034b
// 	0366    57    *JUMPI
// 	0367    60    PUSH1 0x00
// 	0369    80    DUP1
// 	036A    FD    *REVERT
// 	036B    5B    JUMPDEST
// 	036C    50    POP
// 	036D    5A    GAS
// 	036E    F1    CALL
// 	036F    15    ISZERO
// 	0370    80    DUP1
// 	0371    15    ISZERO
// 	0372    61    PUSH2 0x035f
// 	0375    57    *JUMPI
// 	0376    3D    RETURNDATASIZE
// 	0377    60    PUSH1 0x00
// 	0379    80    DUP1
// 	037A    3E    RETURNDATACOPY
// 	037B    3D    RETURNDATASIZE
// 	037C    60    PUSH1 0x00
// 	037E    FD    *REVERT
// 	037F    5B    JUMPDEST
// 	0380    50    POP
// 	0381    50    POP
// 	0382    50    POP
// 	0383    50    POP
// 	0384    50    POP
// 	0385    50    POP
// 	0386    56    *JUMP
// 	0387    5B    JUMPDEST
// 	0388    60    PUSH1 0x02
// 	038A    60    PUSH1 0x14
// 	038C    90    SWAP1
// 	038D    54    SLOAD
// 	038E    90    SWAP1
// 	038F    61    PUSH2 0x0100
// 	0392    0A    EXP
// 	0393    90    SWAP1
// 	0394    04    DIV
// 	0395    60    PUSH1 0xff
// 	0397    16    AND
// 	0398    15    ISZERO
// 	0399    61    PUSH2 0x0381
// 	039C    57    *JUMPI
// 	039D    60    PUSH1 0x00
// 	039F    80    DUP1
// 	03A0    FD    *REVERT
// 	03A1    5B    JUMPDEST
// 	03A2    80    DUP1
// 	03A3    60    PUSH1 0x02
// 	03A5    60    PUSH1 0x00
// 	03A7    61    PUSH2 0x0100
// 	03AA    0A    EXP
// 	03AB    81    DUP2
// 	03AC    54    SLOAD
// 	03AD    81    DUP2
// 	03AE    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	03C3    02    MUL
// 	03C4    19    NOT
// 	03C5    16    AND
// 	03C6    90    SWAP1
// 	03C7    83    DUP4
// 	03C8    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	03DD    16    AND
// 	03DE    02    MUL
// 	03DF    17    OR
// 	03E0    90    SWAP1
// 	03E1    55    SSTORE
// 	03E2    50    POP
// 	03E3    50    POP
// 	03E4    56    *JUMP
// 	03E5    5B    JUMPDEST
// 	03E6    60    PUSH1 0x00
// 	03E8    80    DUP1
// 	03E9    60    PUSH1 0x00
// 	03EB    33    CALLER
// 	03EC    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	0401    16    AND
// 	0402    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	0417    16    AND
// 	0418    81    DUP2
// 	0419    52    MSTORE
// 	041A    60    PUSH1 0x20
// 	041C    01    ADD
// 	041D    90    SWAP1
// 	041E    81    DUP2
// 	041F    52    MSTORE
// 	0420    60    PUSH1 0x20
// 	0422    01    ADD
// 	0423    60    PUSH1 0x00
// 	0425    20    SHA3
// 	0426    90    SWAP1
// 	0427    50    POP
// 	0428    60    PUSH1 0x01
// 	042A    54    SLOAD
// 	042B    81    DUP2
// 	042C    60    PUSH1 0x01
// 	042E    01    ADD
// 	042F    54    SLOAD
// 	0430    10    LT
// 	0431    15    ISZERO
// 	0432    80    DUP1
// 	0433    15    ISZERO
// 	0434    61    PUSH2 0x0421
// 	0437    57    *JUMPI
// 	0438    50    POP
// 	0439    81    DUP2
// 	043A    81    DUP2
// 	043B    60    PUSH1 0x01
// 	043D    01    ADD
// 	043E    54    SLOAD
// 	043F    10    LT
// 	0440    15    ISZERO
// 	0441    5B    JUMPDEST
// 	0442    15    ISZERO
// 	0443    61    PUSH2 0x0581
// 	0446    57    *JUMPI
// 	0447    33    CALLER
// 	0448    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	045D    16    AND
// 	045E    82    DUP3
// 	045F    60    PUSH1 0x40
// 	0461    51    MLOAD
// 	0462    60    PUSH1 0x00
// 	0464    60    PUSH1 0x40
// 	0466    51    MLOAD
// 	0467    80    DUP1
// 	0468    83    DUP4
// 	0469    03    SUB
// 	046A    81    DUP2
// 	046B    85    DUP6
// 	046C    87    DUP8
// 	046D    5A    GAS
// 	046E    F1    CALL
// 	046F    92    SWAP3
// 	0470    50    POP
// 	0471    50    POP
// 	0472    50    POP
// 	0473    15    ISZERO
// 	0474    61    PUSH2 0x0580
// 	0477    57    *JUMPI
// 	0478    81    DUP2
// 	0479    81    DUP2
// 	047A    60    PUSH1 0x01
// 	047C    01    ADD
// 	047D    60    PUSH1 0x00
// 	047F    82    DUP3
// 	0480    82    DUP3
// 	0481    54    SLOAD
// 	0482    03    SUB
// 	0483    92    SWAP3
// 	0484    50    POP
// 	0485    50    POP
// 	0486    81    DUP2
// 	0487    90    SWAP1
// 	0488    55    SSTORE
// 	0489    50    POP
// 	048A    60    PUSH1 0x02
// 	048C    60    PUSH1 0x00
// 	048E    90    SWAP1
// 	048F    54    SLOAD
// 	0490    90    SWAP1
// 	0491    61    PUSH2 0x0100
// 	0494    0A    EXP
// 	0495    90    SWAP1
// 	0496    04    DIV
// 	0497    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	04AC    16    AND
// 	04AD    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	04C2    16    AND
// 	04C3    63    PUSH4 0x4c2f04a4
// 	04C8    33    CALLER
// 	04C9    84    DUP5
// 	04CA    60    PUSH1 0x40
// 	04CC    51    MLOAD
// 	04CD    83    DUP4
// 	04CE    63    PUSH4 0xffffffff
// 	04D3    16    AND
// 	04D4    7C    PUSH29 0x0100000000000000000000000000000000000000000000000000000000
// 	04F2    02    MUL
// 	04F3    81    DUP2
// 	04F4    52    MSTORE
// 	04F5    60    PUSH1 0x04
// 	04F7    01    ADD
// 	04F8    80    DUP1
// 	04F9    83    DUP4
// 	04FA    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	050F    16    AND
// 	0510    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	0525    16    AND
// 	0526    81    DUP2
// 	0527    52    MSTORE
// 	0528    60    PUSH1 0x20
// 	052A    01    ADD
// 	052B    82    DUP3
// 	052C    81    DUP2
// 	052D    52    MSTORE
// 	052E    60    PUSH1 0x20
// 	0530    01    ADD
// 	0531    80    DUP1
// 	0532    60    PUSH1 0x20
// 	0534    01    ADD
// 	0535    82    DUP3
// 	0536    81    DUP2
// 	0537    03    SUB
// 	0538    82    DUP3
// 	0539    52    MSTORE
// 	053A    60    PUSH1 0x07
// 	053C    81    DUP2
// 	053D    52    MSTORE
// 	053E    60    PUSH1 0x20
// 	0540    01    ADD
// 	0541    80    DUP1
// 	0542    7F    PUSH32 0x436f6c6c65637400000000000000000000000000000000000000000000000000
// 	0563    81    DUP2
// 	0564    52    MSTORE
// 	0565    50    POP
// 	0566    60    PUSH1 0x20
// 	0568    01    ADD
// 	0569    93    SWAP4
// 	056A    50    POP
// 	056B    50    POP
// 	056C    50    POP
// 	056D    50    POP
// 	056E    60    PUSH1 0x00
// 	0570    60    PUSH1 0x40
// 	0572    51    MLOAD
// 	0573    80    DUP1
// 	0574    83    DUP4
// 	0575    03    SUB
// 	0576    81    DUP2
// 	0577    60    PUSH1 0x00
// 	0579    87    DUP8
// 	057A    80    DUP1
// 	057B    3B    EXTCODESIZE
// 	057C    15    ISZERO
// 	057D    80    DUP1
// 	057E    15    ISZERO
// 	057F    61    PUSH2 0x0567
// 	0582    57    *JUMPI
// 	0583    60    PUSH1 0x00
// 	0585    80    DUP1
// 	0586    FD    *REVERT
// 	0587    5B    JUMPDEST
// 	0588    50    POP
// 	0589    5A    GAS
// 	058A    F1    CALL
// 	058B    15    ISZERO
// 	058C    80    DUP1
// 	058D    15    ISZERO
// 	058E    61    PUSH2 0x057b
// 	0591    57    *JUMPI
// 	0592    3D    RETURNDATASIZE
// 	0593    60    PUSH1 0x00
// 	0595    80    DUP1
// 	0596    3E    RETURNDATACOPY
// 	0597    3D    RETURNDATASIZE
// 	0598    60    PUSH1 0x00
// 	059A    FD    *REVERT
// 	059B    5B    JUMPDEST
// 	059C    50    POP
// 	059D    50    POP
// 	059E    50    POP
// 	059F    50    POP
// 	05A0    5B    JUMPDEST
// 	05A1    5B    JUMPDEST
// 	05A2    50    POP
// 	05A3    50    POP
// 	05A4    56    *JUMP
// 	05A5    5B    JUMPDEST
// 	05A6    60    PUSH1 0x01
// 	05A8    60    PUSH1 0x02
// 	05AA    60    PUSH1 0x14
// 	05AC    61    PUSH2 0x0100
// 	05AF    0A    EXP
// 	05B0    81    DUP2
// 	05B1    54    SLOAD
// 	05B2    81    DUP2
// 	05B3    60    PUSH1 0xff
// 	05B5    02    MUL
// 	05B6    19    NOT
// 	05B7    16    AND
// 	05B8    90    SWAP1
// 	05B9    83    DUP4
// 	05BA    15    ISZERO
// 	05BB    15    ISZERO
// 	05BC    02    MUL
// 	05BD    17    OR
// 	05BE    90    SWAP1
// 	05BF    55    SSTORE
// 	05C0    50    POP
// 	05C1    56    *JUMP
// 	05C2    5B    JUMPDEST
// 	05C3    60    PUSH1 0x02
// 	05C5    60    PUSH1 0x14
// 	05C7    90    SWAP1
// 	05C8    54    SLOAD
// 	05C9    90    SWAP1
// 	05CA    61    PUSH2 0x0100
// 	05CD    0A    EXP
// 	05CE    90    SWAP1
// 	05CF    04    DIV
// 	05D0    60    PUSH1 0xff
// 	05D2    16    AND
// 	05D3    15    ISZERO
// 	05D4    61    PUSH2 0x05bc
// 	05D7    57    *JUMPI
// 	05D8    60    PUSH1 0x00
// 	05DA    80    DUP1
// 	05DB    FD    *REVERT
// 	05DC    5B    JUMPDEST
// 	05DD    80    DUP1
// 	05DE    60    PUSH1 0x01
// 	05E0    81    DUP2
// 	05E1    90    SWAP1
// 	05E2    55    SSTORE
// 	05E3    50    POP
// 	05E4    50    POP
// 	05E5    56    *JUMP
// 	05E6    5B    JUMPDEST
// 	05E7    60    PUSH1 0x00
// 	05E9    60    PUSH1 0x20
// 	05EB    52    MSTORE
// 	05EC    80    DUP1
// 	05ED    60    PUSH1 0x00
// 	05EF    52    MSTORE
// 	05F0    60    PUSH1 0x40
// 	05F2    60    PUSH1 0x00
// 	05F4    20    SHA3
// 	05F5    60    PUSH1 0x00
// 	05F7    91    SWAP2
// 	05F8    50    POP
// 	05F9    90    SWAP1
// 	05FA    50    POP
// 	05FB    80    DUP1
// 	05FC    60    PUSH1 0x00
// 	05FE    01    ADD
// 	05FF    54    SLOAD
// 	0600    90    SWAP1
// 	0601    80    DUP1
// 	0602    60    PUSH1 0x01
// 	0604    01    ADD
// 	0605    54    SLOAD
// 	0606    90    SWAP1
// 	0607    50    POP
// 	0608    82    DUP3
// 	0609    56    *JUMP
// 	060A    5B    JUMPDEST
// 	060B    60    PUSH1 0x01
// 	060D    54    SLOAD
// 	060E    81    DUP2
// 	060F    56    *JUMP
// 	0610    00    *STOP
// 	0611    A1    LOG1
// 	0612    65    PUSH6 0x627a7a723058
// 	0619    20    SHA3
// 	061A    95    SWAP6
// 	061B    DA    DA
// 	061C    4E    4E
// 	061D    DF    DF
// 	061E    D8    D8
// 	061F    36    CALLDATASIZE
// 	0620    D7    D7
// 	0621    B0    PUSH
// 	0622    C2    C2
// 	0623    89    DUP10
// 	0624    04    DIV
// 	0625    23    23
// 	0626    88    DUP9
// 	0627    4A    4A
// 	0628    D6    D6
// 	0629    4D    4D
// 	062A    90    SWAP1
// 	062B    39    CODECOPY
// 	062C    E0    E0
// 	062D    81    DUP2
// 	062E    F6    F6
// 	062F    5E    5E
// 	0630    F7    F7
// 	0631    E1    E1
// 	0632    16    AND
// 	0633    00    *STOP
// 	0634    CD    CD
// 	0635    35    CALLDATALOAD
// 	0636    E4    E4
// 	0637    D0    D0
// 	0638    53    MSTORE8
// 	0639    FA    STATICCALL
// 	063A    00    *STOP
// 	063B    29    29
// 	063C    60    PUSH1 0x80
// 	063E    60    PUSH1 0x40
// 	0640    52    MSTORE
// 	0641    34    CALLVALUE
// 	0642    80    DUP1
// 	0643    15    ISZERO
// 	0644    61    PUSH2 0x0010
// 	0647    57    *JUMPI
// 	0648    60    PUSH1 0x00
// 	064A    80    DUP1
// 	064B    FD    *REVERT
// 	064C    5B    JUMPDEST
// 	064D    50    POP
// 	064E    61    PUSH2 0x0565
// 	0651    80    DUP1
// 	0652    61    PUSH2 0x0020
// 	0655    60    PUSH1 0x00
// 	0657    39    CODECOPY
// 	0658    60    PUSH1 0x00
// 	065A    F3    *RETURN
// 	065B    00    *STOP
// 	065C    60    PUSH1 0x80
// 	065E    60    PUSH1 0x40
// 	0660    52    MSTORE
// 	0661    60    PUSH1 0x04
// 	0663    36    CALLDATASIZE
// 	0664    10    LT
// 	0665    61    PUSH2 0x004c
// 	0668    57    *JUMPI
// 	0669    60    PUSH1 0x00
// 	066B    35    CALLDATALOAD
// 	066C    7C    PUSH29 0x0100000000000000000000000000000000000000000000000000000000
// 	068A    90    SWAP1
// 	068B    04    DIV
// 	068C    63    PUSH4 0xffffffff
// 	0691    16    AND
// 	0692    80    DUP1
// 	0693    63    PUSH4 0x4c2f04a4
// 	0698    14    EQ
// 	0699    61    PUSH2 0x0051
// 	069C    57    *JUMPI
// 	069D    80    DUP1
// 	069E    63    PUSH4 0xa21f0368
// 	06A3    14    EQ
// 	06A4    61    PUSH2 0x00e4
// 	06A7    57    *JUMPI
// 	06A8    5B    JUMPDEST
// 	06A9    60    PUSH1 0x00
// 	06AB    80    DUP1
// 	06AC    FD    *REVERT
// 	06AD    5B    JUMPDEST
// 	06AE    34    CALLVALUE
// 	06AF    80    DUP1
// 	06B0    15    ISZERO
// 	06B1    61    PUSH2 0x005d
// 	06B4    57    *JUMPI
// 	06B5    60    PUSH1 0x00
// 	06B7    80    DUP1
// 	06B8    FD    *REVERT
// 	06B9    5B    JUMPDEST
// 	06BA    50    POP
// 	06BB    61    PUSH2 0x00e2
// 	06BE    60    PUSH1 0x04
// 	06C0    80    DUP1
// 	06C1    36    CALLDATASIZE
// 	06C2    03    SUB
// 	06C3    81    DUP2
// 	06C4    01    ADD
// 	06C5    90    SWAP1
// 	06C6    80    DUP1
// 	06C7    80    DUP1
// 	06C8    35    CALLDATALOAD
// 	06C9    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	06DE    16    AND
// 	06DF    90    SWAP1
// 	06E0    60    PUSH1 0x20
// 	06E2    01    ADD
// 	06E3    90    SWAP1
// 	06E4    92    SWAP3
// 	06E5    91    SWAP2
// 	06E6    90    SWAP1
// 	06E7    80    DUP1
// 	06E8    35    CALLDATALOAD
// 	06E9    90    SWAP1
// 	06EA    60    PUSH1 0x20
// 	06EC    01    ADD
// 	06ED    90    SWAP1
// 	06EE    92    SWAP3
// 	06EF    91    SWAP2
// 	06F0    90    SWAP1
// 	06F1    80    DUP1
// 	06F2    35    CALLDATALOAD
// 	06F3    90    SWAP1
// 	06F4    60    PUSH1 0x20
// 	06F6    01    ADD
// 	06F7    90    SWAP1
// 	06F8    82    DUP3
// 	06F9    01    ADD
// 	06FA    80    DUP1
// 	06FB    35    CALLDATALOAD
// 	06FC    90    SWAP1
// 	06FD    60    PUSH1 0x20
// 	06FF    01    ADD
// 	0700    90    SWAP1
// 	0701    80    DUP1
// 	0702    80    DUP1
// 	0703    60    PUSH1 0x1f
// 	0705    01    ADD
// 	0706    60    PUSH1 0x20
// 	0708    80    DUP1
// 	0709    91    SWAP2
// 	070A    04    DIV
// 	070B    02    MUL
// 	070C    60    PUSH1 0x20
// 	070E    01    ADD
// 	070F    60    PUSH1 0x40
// 	0711    51    MLOAD
// 	0712    90    SWAP1
// 	0713    81    DUP2
// 	0714    01    ADD
// 	0715    60    PUSH1 0x40
// 	0717    52    MSTORE
// 	0718    80    DUP1
// 	0719    93    SWAP4
// 	071A    92    SWAP3
// 	071B    91    SWAP2
// 	071C    90    SWAP1
// 	071D    81    DUP2
// 	071E    81    DUP2
// 	071F    52    MSTORE
// 	0720    60    PUSH1 0x20
// 	0722    01    ADD
// 	0723    83    DUP4
// 	0724    83    DUP4
// 	0725    80    DUP1
// 	0726    82    DUP3
// 	0727    84    DUP5
// 	0728    37    CALLDATACOPY
// 	0729    82    DUP3
// 	072A    01    ADD
// 	072B    91    SWAP2
// 	072C    50    POP
// 	072D    50    POP
// 	072E    50    POP
// 	072F    50    POP
// 	0730    50    POP
// 	0731    50    POP
// 	0732    91    SWAP2
// 	0733    92    SWAP3
// 	0734    91    SWAP2
// 	0735    92    SWAP3
// 	0736    90    SWAP1
// 	0737    50    POP
// 	0738    50    POP
// 	0739    50    POP
// 	073A    61    PUSH2 0x01cb
// 	073D    56    *JUMP
// 	073E    5B    JUMPDEST
// 	073F    00    *STOP
// 	0740    5B    JUMPDEST
// 	0741    34    CALLVALUE
// 	0742    80    DUP1
// 	0743    15    ISZERO
// 	0744    61    PUSH2 0x00f0
// 	0747    57    *JUMPI
// 	0748    60    PUSH1 0x00
// 	074A    80    DUP1
// 	074B    FD    *REVERT
// 	074C    5B    JUMPDEST
// 	074D    50    POP
// 	074E    61    PUSH2 0x010f
// 	0751    60    PUSH1 0x04
// 	0753    80    DUP1
// 	0754    36    CALLDATASIZE
// 	0755    03    SUB
// 	0756    81    DUP2
// 	0757    01    ADD
// 	0758    90    SWAP1
// 	0759    80    DUP1
// 	075A    80    DUP1
// 	075B    35    CALLDATALOAD
// 	075C    90    SWAP1
// 	075D    60    PUSH1 0x20
// 	075F    01    ADD
// 	0760    90    SWAP1
// 	0761    92    SWAP3
// 	0762    91    SWAP2
// 	0763    90    SWAP1
// 	0764    50    POP
// 	0765    50    POP
// 	0766    50    POP
// 	0767    61    PUSH2 0x0316
// 	076A    56    *JUMP
// 	076B    5B    JUMPDEST
// 	076C    60    PUSH1 0x40
// 	076E    51    MLOAD
// 	076F    80    DUP1
// 	0770    85    DUP6
// 	0771    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	0786    16    AND
// 	0787    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	079C    16    AND
// 	079D    81    DUP2
// 	079E    52    MSTORE
// 	079F    60    PUSH1 0x20
// 	07A1    01    ADD
// 	07A2    80    DUP1
// 	07A3    60    PUSH1 0x20
// 	07A5    01    ADD
// 	07A6    84    DUP5
// 	07A7    81    DUP2
// 	07A8    52    MSTORE
// 	07A9    60    PUSH1 0x20
// 	07AB    01    ADD
// 	07AC    83    DUP4
// 	07AD    81    DUP2
// 	07AE    52    MSTORE
// 	07AF    60    PUSH1 0x20
// 	07B1    01    ADD
// 	07B2    82    DUP3
// 	07B3    81    DUP2
// 	07B4    03    SUB
// 	07B5    82    DUP3
// 	07B6    52    MSTORE
// 	07B7    85    DUP6
// 	07B8    81    DUP2
// 	07B9    81    DUP2
// 	07BA    51    MLOAD
// 	07BB    81    DUP2
// 	07BC    52    MSTORE
// 	07BD    60    PUSH1 0x20
// 	07BF    01    ADD
// 	07C0    91    SWAP2
// 	07C1    50    POP
// 	07C2    80    DUP1
// 	07C3    51    MLOAD
// 	07C4    90    SWAP1
// 	07C5    60    PUSH1 0x20
// 	07C7    01    ADD
// 	07C8    90    SWAP1
// 	07C9    80    DUP1
// 	07CA    83    DUP4
// 	07CB    83    DUP4
// 	07CC    60    PUSH1 0x00
// 	07CE    5B    JUMPDEST
// 	07CF    83    DUP4
// 	07D0    81    DUP2
// 	07D1    10    LT
// 	07D2    15    ISZERO
// 	07D3    61    PUSH2 0x018d
// 	07D6    57    *JUMPI
// 	07D7    80    DUP1
// 	07D8    82    DUP3
// 	07D9    01    ADD
// 	07DA    51    MLOAD
// 	07DB    81    DUP2
// 	07DC    84    DUP5
// 	07DD    01    ADD
// 	07DE    52    MSTORE
// 	07DF    60    PUSH1 0x20
// 	07E1    81    DUP2
// 	07E2    01    ADD
// 	07E3    90    SWAP1
// 	07E4    50    POP
// 	07E5    61    PUSH2 0x0172
// 	07E8    56    *JUMP
// 	07E9    5B    JUMPDEST
// 	07EA    50    POP
// 	07EB    50    POP
// 	07EC    50    POP
// 	07ED    50    POP
// 	07EE    90    SWAP1
// 	07EF    50    POP
// 	07F0    90    SWAP1
// 	07F1    81    DUP2
// 	07F2    01    ADD
// 	07F3    90    SWAP1
// 	07F4    60    PUSH1 0x1f
// 	07F6    16    AND
// 	07F7    80    DUP1
// 	07F8    15    ISZERO
// 	07F9    61    PUSH2 0x01ba
// 	07FC    57    *JUMPI
// 	07FD    80    DUP1
// 	07FE    82    DUP3
// 	07FF    03    SUB
// 	0800    80    DUP1
// 	0801    51    MLOAD
// 	0802    60    PUSH1 0x01
// 	0804    83    DUP4
// 	0805    60    PUSH1 0x20
// 	0807    03    SUB
// 	0808    61    PUSH2 0x0100
// 	080B    0A    EXP
// 	080C    03    SUB
// 	080D    19    NOT
// 	080E    16    AND
// 	080F    81    DUP2
// 	0810    52    MSTORE
// 	0811    60    PUSH1 0x20
// 	0813    01    ADD
// 	0814    91    SWAP2
// 	0815    50    POP
// 	0816    5B    JUMPDEST
// 	0817    50    POP
// 	0818    95    SWAP6
// 	0819    50    POP
// 	081A    50    POP
// 	081B    50    POP
// 	081C    50    POP
// 	081D    50    POP
// 	081E    50    POP
// 	081F    60    PUSH1 0x40
// 	0821    51    MLOAD
// 	0822    80    DUP1
// 	0823    91    SWAP2
// 	0824    03    SUB
// 	0825    90    SWAP1
// 	0826    F3    *RETURN
// 	0827    5B    JUMPDEST
// 	0828    82    DUP3
// 	0829    60    PUSH1 0x01
// 	082B    60    PUSH1 0x00
// 	082D    01    ADD
// 	082E    60    PUSH1 0x00
// 	0830    61    PUSH2 0x0100
// 	0833    0A    EXP
// 	0834    81    DUP2
// 	0835    54    SLOAD
// 	0836    81    DUP2
// 	0837    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	084C    02    MUL
// 	084D    19    NOT
// 	084E    16    AND
// 	084F    90    SWAP1
// 	0850    83    DUP4
// 	0851    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	0866    16    AND
// 	0867    02    MUL
// 	0868    17    OR
// 	0869    90    SWAP1
// 	086A    55    SSTORE
// 	086B    50    POP
// 	086C    42    TIMESTAMP
// 	086D    60    PUSH1 0x01
// 	086F    60    PUSH1 0x03
// 	0871    01    ADD
// 	0872    81    DUP2
// 	0873    90    SWAP1
// 	0874    55    SSTORE
// 	0875    50    POP
// 	0876    81    DUP2
// 	0877    60    PUSH1 0x01
// 	0879    60    PUSH1 0x02
// 	087B    01    ADD
// 	087C    81    DUP2
// 	087D    90    SWAP1
// 	087E    55    SSTORE
// 	087F    50    POP
// 	0880    80    DUP1
// 	0881    60    PUSH1 0x01
// 	0883    80    DUP1
// 	0884    01    ADD
// 	0885    90    SWAP1
// 	0886    80    DUP1
// 	0887    51    MLOAD
// 	0888    90    SWAP1
// 	0889    60    PUSH1 0x20
// 	088B    01    ADD
// 	088C    90    SWAP1
// 	088D    61    PUSH2 0x023b
// 	0890    92    SWAP3
// 	0891    91    SWAP2
// 	0892    90    SWAP1
// 	0893    61    PUSH2 0x040d
// 	0896    56    *JUMP
// 	0897    5B    JUMPDEST
// 	0898    50    POP
// 	0899    60    PUSH1 0x00
// 	089B    60    PUSH1 0x01
// 	089D    90    SWAP1
// 	089E    80    DUP1
// 	089F    60    PUSH1 0x01
// 	08A1    81    DUP2
// 	08A2    54    SLOAD
// 	08A3    01    ADD
// 	08A4    80    DUP1
// 	08A5    82    DUP3
// 	08A6    55    SSTORE
// 	08A7    80    DUP1
// 	08A8    91    SWAP2
// 	08A9    50    POP
// 	08AA    50    POP
// 	08AB    90    SWAP1
// 	08AC    60    PUSH1 0x01
// 	08AE    82    DUP3
// 	08AF    03    SUB
// 	08B0    90    SWAP1
// 	08B1    60    PUSH1 0x00
// 	08B3    52    MSTORE
// 	08B4    60    PUSH1 0x20
// 	08B6    60    PUSH1 0x00
// 	08B8    20    SHA3
// 	08B9    90    SWAP1
// 	08BA    60    PUSH1 0x04
// 	08BC    02    MUL
// 	08BD    01    ADD
// 	08BE    60    PUSH1 0x00
// 	08C0    90    SWAP1
// 	08C1    91    SWAP2
// 	08C2    92    SWAP3
// 	08C3    90    SWAP1
// 	08C4    91    SWAP2
// 	08C5    90    SWAP1
// 	08C6    91    SWAP2
// 	08C7    50    POP
// 	08C8    60    PUSH1 0x00
// 	08CA    82    DUP3
// 	08CB    01    ADD
// 	08CC    60    PUSH1 0x00
// 	08CE    90    SWAP1
// 	08CF    54    SLOAD
// 	08D0    90    SWAP1
// 	08D1    61    PUSH2 0x0100
// 	08D4    0A    EXP
// 	08D5    90    SWAP1
// 	08D6    04    DIV
// 	08D7    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	08EC    16    AND
// 	08ED    81    DUP2
// 	08EE    60    PUSH1 0x00
// 	08F0    01    ADD
// 	08F1    60    PUSH1 0x00
// 	08F3    61    PUSH2 0x0100
// 	08F6    0A    EXP
// 	08F7    81    DUP2
// 	08F8    54    SLOAD
// 	08F9    81    DUP2
// 	08FA    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	090F    02    MUL
// 	0910    19    NOT
// 	0911    16    AND
// 	0912    90    SWAP1
// 	0913    83    DUP4
// 	0914    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	0929    16    AND
// 	092A    02    MUL
// 	092B    17    OR
// 	092C    90    SWAP1
// 	092D    55    SSTORE
// 	092E    50    POP
// 	092F    60    PUSH1 0x01
// 	0931    82    DUP3
// 	0932    01    ADD
// 	0933    81    DUP2
// 	0934    60    PUSH1 0x01
// 	0936    01    ADD
// 	0937    90    SWAP1
// 	0938    80    DUP1
// 	0939    54    SLOAD
// 	093A    60    PUSH1 0x01
// 	093C    81    DUP2
// 	093D    60    PUSH1 0x01
// 	093F    16    AND
// 	0940    15    ISZERO
// 	0941    61    PUSH2 0x0100
// 	0944    02    MUL
// 	0945    03    SUB
// 	0946    16    AND
// 	0947    60    PUSH1 0x02
// 	0949    90    SWAP1
// 	094A    04    DIV
// 	094B    61    PUSH2 0x02f9
// 	094E    92    SWAP3
// 	094F    91    SWAP2
// 	0950    90    SWAP1
// 	0951    61    PUSH2 0x048d
// 	0954    56    *JUMP
// 	0955    5B    JUMPDEST
// 	0956    50    POP
// 	0957    60    PUSH1 0x02
// 	0959    82    DUP3
// 	095A    01    ADD
// 	095B    54    SLOAD
// 	095C    81    DUP2
// 	095D    60    PUSH1 0x02
// 	095F    01    ADD
// 	0960    55    SSTORE
// 	0961    60    PUSH1 0x03
// 	0963    82    DUP3
// 	0964    01    ADD
// 	0965    54    SLOAD
// 	0966    81    DUP2
// 	0967    60    PUSH1 0x03
// 	0969    01    ADD
// 	096A    55    SSTORE
// 	096B    50    POP
// 	096C    50    POP
// 	096D    50    POP
// 	096E    50    POP
// 	096F    50    POP
// 	0970    50    POP
// 	0971    56    *JUMP
// 	0972    5B    JUMPDEST
// 	0973    60    PUSH1 0x00
// 	0975    81    DUP2
// 	0976    81    DUP2
// 	0977    54    SLOAD
// 	0978    81    DUP2
// 	0979    10    LT
// 	097A    15    ISZERO
// 	097B    15    ISZERO
// 	097C    61    PUSH2 0x0325
// 	097F    57    *JUMPI
// 	0980    FE    *ASSERT
// 	0981    5B    JUMPDEST
// 	0982    90    SWAP1
// 	0983    60    PUSH1 0x00
// 	0985    52    MSTORE
// 	0986    60    PUSH1 0x20
// 	0988    60    PUSH1 0x00
// 	098A    20    SHA3
// 	098B    90    SWAP1
// 	098C    60    PUSH1 0x04
// 	098E    02    MUL
// 	098F    01    ADD
// 	0990    60    PUSH1 0x00
// 	0992    91    SWAP2
// 	0993    50    POP
// 	0994    90    SWAP1
// 	0995    50    POP
// 	0996    80    DUP1
// 	0997    60    PUSH1 0x00
// 	0999    01    ADD
// 	099A    60    PUSH1 0x00
// 	099C    90    SWAP1
// 	099D    54    SLOAD
// 	099E    90    SWAP1
// 	099F    61    PUSH2 0x0100
// 	09A2    0A    EXP
// 	09A3    90    SWAP1
// 	09A4    04    DIV
// 	09A5    73    PUSH20 0xffffffffffffffffffffffffffffffffffffffff
// 	09BA    16    AND
// 	09BB    90    SWAP1
// 	09BC    80    DUP1
// 	09BD    60    PUSH1 0x01
// 	09BF    01    ADD
// 	09C0    80    DUP1
// 	09C1    54    SLOAD
// 	09C2    60    PUSH1 0x01
// 	09C4    81    DUP2
// 	09C5    60    PUSH1 0x01
// 	09C7    16    AND
// 	09C8    15    ISZERO
// 	09C9    61    PUSH2 0x0100
// 	09CC    02    MUL
// 	09CD    03    SUB
// 	09CE    16    AND
// 	09CF    60    PUSH1 0x02
// 	09D1    90    SWAP1
// 	09D2    04    DIV
// 	09D3    80    DUP1
// 	09D4    60    PUSH1 0x1f
// 	09D6    01    ADD
// 	09D7    60    PUSH1 0x20
// 	09D9    80    DUP1
// 	09DA    91    SWAP2
// 	09DB    04    DIV
// 	09DC    02    MUL
// 	09DD    60    PUSH1 0x20
// 	09DF    01    ADD
// 	09E0    60    PUSH1 0x40
// 	09E2    51    MLOAD
// 	09E3    90    SWAP1
// 	09E4    81    DUP2
// 	09E5    01    ADD
// 	09E6    60    PUSH1 0x40
// 	09E8    52    MSTORE
// 	09E9    80    DUP1
// 	09EA    92    SWAP3
// 	09EB    91    SWAP2
// 	09EC    90    SWAP1
// 	09ED    81    DUP2
// 	09EE    81    DUP2
// 	09EF    52    MSTORE
// 	09F0    60    PUSH1 0x20
// 	09F2    01    ADD
// 	09F3    82    DUP3
// 	09F4    80    DUP1
// 	09F5    54    SLOAD
// 	09F6    60    PUSH1 0x01
// 	09F8    81    DUP2
// 	09F9    60    PUSH1 0x01
// 	09FB    16    AND
// 	09FC    15    ISZERO
// 	09FD    61    PUSH2 0x0100
// 	0A00    02    MUL
// 	0A01    03    SUB
// 	0A02    16    AND
// 	0A03    60    PUSH1 0x02
// 	0A05    90    SWAP1
// 	0A06    04    DIV
// 	0A07    80    DUP1
// 	0A08    15    ISZERO
// 	0A09    61    PUSH2 0x03f7
// 	0A0C    57    *JUMPI
// 	0A0D    80    DUP1
// 	0A0E    60    PUSH1 0x1f
// 	0A10    10    LT
// 	0A11    61    PUSH2 0x03cc
// 	0A14    57    *JUMPI
// 	0A15    61    PUSH2 0x0100
// 	0A18    80    DUP1
// 	0A19    83    DUP4
// 	0A1A    54    SLOAD
// 	0A1B    04    DIV
// 	0A1C    02    MUL
// 	0A1D    83    DUP4
// 	0A1E    52    MSTORE
// 	0A1F    91    SWAP2
// 	0A20    60    PUSH1 0x20
// 	0A22    01    ADD
// 	0A23    91    SWAP2
// 	0A24    61    PUSH2 0x03f7
// 	0A27    56    *JUMP
// 	0A28    5B    JUMPDEST
// 	0A29    82    DUP3
// 	0A2A    01    ADD
// 	0A2B    91    SWAP2
// 	0A2C    90    SWAP1
// 	0A2D    60    PUSH1 0x00
// 	0A2F    52    MSTORE
// 	0A30    60    PUSH1 0x20
// 	0A32    60    PUSH1 0x00
// 	0A34    20    SHA3
// 	0A35    90    SWAP1
// 	0A36    5B    JUMPDEST
// 	0A37    81    DUP2
// 	0A38    54    SLOAD
// 	0A39    81    DUP2
// 	0A3A    52    MSTORE
// 	0A3B    90    SWAP1
// 	0A3C    60    PUSH1 0x01
// 	0A3E    01    ADD
// 	0A3F    90    SWAP1
// 	0A40    60    PUSH1 0x20
// 	0A42    01    ADD
// 	0A43    80    DUP1
// 	0A44    83    DUP4
// 	0A45    11    GT
// 	0A46    61    PUSH2 0x03da
// 	0A49    57    *JUMPI
// 	0A4A    82    DUP3
// 	0A4B    90    SWAP1
// 	0A4C    03    SUB
// 	0A4D    60    PUSH1 0x1f
// 	0A4F    16    AND
// 	0A50    82    DUP3
// 	0A51    01    ADD
// 	0A52    91    SWAP2
// 	0A53    5B    JUMPDEST
// 	0A54    50    POP
// 	0A55    50    POP
// 	0A56    50    POP
// 	0A57    50    POP
// 	0A58    50    POP
// 	0A59    90    SWAP1
// 	0A5A    80    DUP1
// 	0A5B    60    PUSH1 0x02
// 	0A5D    01    ADD
// 	0A5E    54    SLOAD
// 	0A5F    90    SWAP1
// 	0A60    80    DUP1
// 	0A61    60    PUSH1 0x03
// 	0A63    01    ADD
// 	0A64    54    SLOAD
// 	0A65    90    SWAP1
// 	0A66    50    POP
// 	0A67    84    DUP5
// 	0A68    56    *JUMP
// 	0A69    5B    JUMPDEST
// 	0A6A    82    DUP3
// 	0A6B    80    DUP1
// 	0A6C    54    SLOAD
// 	0A6D    60    PUSH1 0x01
// 	0A6F    81    DUP2
// 	0A70    60    PUSH1 0x01
// 	0A72    16    AND
// 	0A73    15    ISZERO
// 	0A74    61    PUSH2 0x0100
// 	0A77    02    MUL
// 	0A78    03    SUB
// 	0A79    16    AND
// 	0A7A    60    PUSH1 0x02
// 	0A7C    90    SWAP1
// 	0A7D    04    DIV
// 	0A7E    90    SWAP1
// 	0A7F    60    PUSH1 0x00
// 	0A81    52    MSTORE
// 	0A82    60    PUSH1 0x20
// 	0A84    60    PUSH1 0x00
// 	0A86    20    SHA3
// 	0A87    90    SWAP1
// 	0A88    60    PUSH1 0x1f
// 	0A8A    01    ADD
// 	0A8B    60    PUSH1 0x20
// 	0A8D    90    SWAP1
// 	0A8E    04    DIV
// 	0A8F    81    DUP2
// 	0A90    01    ADD
// 	0A91    92    SWAP3
// 	0A92    82    DUP3
// 	0A93    60    PUSH1 0x1f
// 	0A95    10    LT
// 	0A96    61    PUSH2 0x044e
// 	0A99    57    *JUMPI
// 	0A9A    80    DUP1
// 	0A9B    51    MLOAD
// 	0A9C    60    PUSH1 0xff
// 	0A9E    19    NOT
// 	0A9F    16    AND
// 	0AA0    83    DUP4
// 	0AA1    80    DUP1
// 	0AA2    01    ADD
// 	0AA3    17    OR
// 	0AA4    85    DUP6
// 	0AA5    55    SSTORE
// 	0AA6    61    PUSH2 0x047c
// 	0AA9    56    *JUMP
// 	0AAA    5B    JUMPDEST
// 	0AAB    82    DUP3
// 	0AAC    80    DUP1
// 	0AAD    01    ADD
// 	0AAE    60    PUSH1 0x01
// 	0AB0    01    ADD
// 	0AB1    85    DUP6
// 	0AB2    55    SSTORE
// 	0AB3    82    DUP3
// 	0AB4    15    ISZERO
// 	0AB5    61    PUSH2 0x047c
// 	0AB8    57    *JUMPI
// 	0AB9    91    SWAP2
// 	0ABA    82    DUP3
// 	0ABB    01    ADD
// 	0ABC    5B    JUMPDEST
// 	0ABD    82    DUP3
// 	0ABE    81    DUP2
// 	0ABF    11    GT
// 	0AC0    15    ISZERO
// 	0AC1    61    PUSH2 0x047b
// 	0AC4    57    *JUMPI
// 	0AC5    82    DUP3
// 	0AC6    51    MLOAD
// 	0AC7    82    DUP3
// 	0AC8    55    SSTORE
// 	0AC9    91    SWAP2
// 	0ACA    60    PUSH1 0x20
// 	0ACC    01    ADD
// 	0ACD    91    SWAP2
// 	0ACE    90    SWAP1
// 	0ACF    60    PUSH1 0x01
// 	0AD1    01    ADD
// 	0AD2    90    SWAP1
// 	0AD3    61    PUSH2 0x0460
// 	0AD6    56    *JUMP
// 	0AD7    5B    JUMPDEST
// 	0AD8    5B    JUMPDEST
// 	0AD9    50    POP
// 	0ADA    90    SWAP1
// 	0ADB    50    POP
// 	0ADC    61    PUSH2 0x0489
// 	0ADF    91    SWAP2
// 	0AE0    90    SWAP1
// 	0AE1    61    PUSH2 0x0514
// 	0AE4    56    *JUMP
// 	0AE5    5B    JUMPDEST
// 	0AE6    50    POP
// 	0AE7    90    SWAP1
// 	0AE8    56    *JUMP
// 	0AE9    5B    JUMPDEST
// 	0AEA    82    DUP3
// 	0AEB    80    DUP1
// 	0AEC    54    SLOAD
// 	0AED    60    PUSH1 0x01
// 	0AEF    81    DUP2
// 	0AF0    60    PUSH1 0x01
// 	0AF2    16    AND
// 	0AF3    15    ISZERO
// 	0AF4    61    PUSH2 0x0100
// 	0AF7    02    MUL
// 	0AF8    03    SUB
// 	0AF9    16    AND
// 	0AFA    60    PUSH1 0x02
// 	0AFC    90    SWAP1
// 	0AFD    04    DIV
// 	0AFE    90    SWAP1
// 	0AFF    60    PUSH1 0x00
// 	0B01    52    MSTORE
// 	0B02    60    PUSH1 0x20
// 	0B04    60    PUSH1 0x00
// 	0B06    20    SHA3
// 	0B07    90    SWAP1
// 	0B08    60    PUSH1 0x1f
// 	0B0A    01    ADD
// 	0B0B    60    PUSH1 0x20
// 	0B0D    90    SWAP1
// 	0B0E    04    DIV
// 	0B0F    81    DUP2
// 	0B10    01    ADD
// 	0B11    92    SWAP3
// 	0B12    82    DUP3
// 	0B13    60    PUSH1 0x1f
// 	0B15    10    LT
// 	0B16    61    PUSH2 0x04c6
// 	0B19    57    *JUMPI
// 	0B1A    80    DUP1
// 	0B1B    54    SLOAD
// 	0B1C    85    DUP6
// 	0B1D    55    SSTORE
// 	0B1E    61    PUSH2 0x0503
// 	0B21    56    *JUMP
// 	0B22    5B    JUMPDEST
// 	0B23    82    DUP3
// 	0B24    80    DUP1
// 	0B25    01    ADD
// 	0B26    60    PUSH1 0x01
// 	0B28    01    ADD
// 	0B29    85    DUP6
// 	0B2A    55    SSTORE
// 	0B2B    82    DUP3
// 	0B2C    15    ISZERO
// 	0B2D    61    PUSH2 0x0503
// 	0B30    57    *JUMPI
// 	0B31    60    PUSH1 0x00
// 	0B33    52    MSTORE
// 	0B34    60    PUSH1 0x20
// 	0B36    60    PUSH1 0x00
// 	0B38    20    SHA3
// 	0B39    91    SWAP2
// 	0B3A    60    PUSH1 0x1f
// 	0B3C    01    ADD
// 	0B3D    60    PUSH1 0x20
// 	0B3F    90    SWAP1
// 	0B40    04    DIV
// 	0B41    82    DUP3
// 	0B42    01    ADD
// 	0B43    5B    JUMPDEST
// 	0B44    82    DUP3
// 	0B45    81    DUP2
// 	0B46    11    GT
// 	0B47    15    ISZERO
// 	0B48    61    PUSH2 0x0502
// 	0B4B    57    *JUMPI
// 	0B4C    82    DUP3
// 	0B4D    54    SLOAD
// 	0B4E    82    DUP3
// 	0B4F    55    SSTORE
// 	0B50    91    SWAP2
// 	0B51    60    PUSH1 0x01
// 	0B53    01    ADD
// 	0B54    91    SWAP2
// 	0B55    90    SWAP1
// 	0B56    60    PUSH1 0x01
// 	0B58    01    ADD
// 	0B59    90    SWAP1
// 	0B5A    61    PUSH2 0x04e7
// 	0B5D    56    *JUMP
// 	0B5E    5B    JUMPDEST
// 	0B5F    5B    JUMPDEST
// 	0B60    50    POP
// 	0B61    90    SWAP1
// 	0B62    50    POP
// 	0B63    61    PUSH2 0x0510
// 	0B66    91    SWAP2
// 	0B67    90    SWAP1
// 	0B68    61    PUSH2 0x0514
// 	0B6B    56    *JUMP
// 	0B6C    5B    JUMPDEST
// 	0B6D    50    POP
// 	0B6E    90    SWAP1
// 	0B6F    56    *JUMP
// 	0B70    5B    JUMPDEST
// 	0B71    61    PUSH2 0x0536
// 	0B74    91    SWAP2
// 	0B75    90    SWAP1
// 	0B76    5B    JUMPDEST
// 	0B77    80    DUP1
// 	0B78    82    DUP3
// 	0B79    11    GT
// 	0B7A    15    ISZERO
// 	0B7B    61    PUSH2 0x0532
// 	0B7E    57    *JUMPI
// 	0B7F    60    PUSH1 0x00
// 	0B81    81    DUP2
// 	0B82    60    PUSH1 0x00
// 	0B84    90    SWAP1
// 	0B85    55    SSTORE
// 	0B86    50    POP
// 	0B87    60    PUSH1 0x01
// 	0B89    01    ADD
// 	0B8A    61    PUSH2 0x051a
// 	0B8D    56    *JUMP
// 	0B8E    5B    JUMPDEST
// 	0B8F    50    POP
// 	0B90    90    SWAP1
// 	0B91    56    *JUMP
// 	0B92    5B    JUMPDEST
// 	0B93    90    SWAP1
// 	0B94    56    *JUMP
// 	0B95    00    *STOP
// 	0B96    A1    LOG1
// 	0B97    65    PUSH6 0x627a7a723058
// 	0B9E    20    SHA3
// 	0B9F    C8    C8
// 	0BA0    68    PUSH9 0x5b780429565091469e
// 	0BAA    44    DIFFICULTY
// 	0BAB    54    SLOAD
// 	0BAC    01    ADD
// 	0BAD    57    *JUMPI
// 	0BAE    9A    SWAP11
// 	0BAF    AE    AE
// 	0BB0    AC    AC
// 	0BB1    78    PUSH25 0x96dce0ed173fda4f40e8eb47250029