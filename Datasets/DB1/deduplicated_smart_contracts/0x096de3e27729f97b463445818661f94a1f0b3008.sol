/**

 *Submitted for verification at Etherscan.io on 2019-03-27

*/



pragma solidity ^0.4.24;

 

/**

 * @title ERC20Basic

 * @dev Simpler version of ERC20 interface

 * See https://github.com/ethereum/EIPs/issues/179

 */

contract ERC20Basic {

  function totalSupply() public view returns (uint256);

  function balanceOf(address who) public view returns (uint256);

  function transfer(address to, uint256 value) public returns (bool);

  event Transfer(address indexed from, address indexed to, uint256 value);

}

 

/**

 * @title ERC20 interface

 * @dev see https://github.com/ethereum/EIPs/issues/20

 */

contract ERC20 is ERC20Basic {

  function allowance(address owner, address spender) public view returns (uint256);

  function transferFrom(address from, address to, uint256 value) public returns (bool);

  function approve(address spender, uint256 value) public returns (bool);

  event Approval(

    address indexed owner,

    address indexed spender,

    uint256 value

  );

}

 

/**

 * @title SafeMath

 * @dev Math operations with safety checks that throw on error

 */

library SafeMath {

 

  /**

  * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).

  */

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {

    assert(b <= a);

    return a - b;

  }

 

  /**

  * @dev Adds two numbers, throws on overflow.

  */

  function add(uint256 a, uint256 b) internal pure returns (uint256 c) {

    c = a + b;

    assert(c >= a);

    return c;

  }

}

 

/**

 * @title Basic token

 * @dev Basic version of StandardToken, with no allowances.

 */

contract BasicToken is ERC20Basic {

  using SafeMath for uint256;

 

  mapping(address => uint256) balances;

 

  uint256 totalSupply_;

 

  /**

  * @dev Total number of tokens in existence

  */

  function totalSupply() public view returns (uint256) {

    return totalSupply_;

  }

 

  /**

  * @dev Transfer token for a specified address

  * @param _to The address to transfer to.

  * @param _value The amount to be transferred.

  */

  function transfer(address _to, uint256 _value) public returns (bool) {

    require(_to != address(0));

    require(_value <= balances[msg.sender]);

 

    balances[msg.sender] = balances[msg.sender].sub(_value);

    balances[_to] = balances[_to].add(_value);

    emit Transfer(msg.sender, _to, _value);

    return true;

  }

 

  /**

  * @dev Gets the balance of the specified address.

  * @param _owner The address to query the the balance of.

  * @return An uint256 representing the amount owned by the passed address.

  */

  function balanceOf(address _owner) public view returns (uint256) {

    return balances[_owner];

  }

 

}

 

/**

 * @title Standard ERC20 token

 *

 * @dev Implementation of the basic standard token.

 * https://github.com/ethereum/EIPs/issues/20

 * Based on code by FirstBlood: https://github.com/Firstbloodio/token/blob/master/smart_contract/FirstBloodToken.sol

 */

contract StandardToken is ERC20, BasicToken {

 

  mapping (address => mapping (address => uint256)) internal allowed;

 

 

  /**

   * @dev Transfer tokens from one address to another

   * @param _from address The address which you want to send tokens from

   * @param _to address The address which you want to transfer to

   * @param _value uint256 the amount of tokens to be transferred

   */

  function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {

    require(_to != address(0));

    require(_value <= balances[_from]);

    require(_value <= allowed[_from][msg.sender]);

 

    balances[_from] = balances[_from].sub(_value);

    balances[_to] = balances[_to].add(_value);

    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);

    emit Transfer(_from, _to, _value);

    return true;

  }

 

  /**

   * @dev Approve the passed address to spend the specified amount of tokens on behalf of msg.sender.

   * Beware that changing an allowance with this method brings the risk that someone may use both the old

   * and the new allowance by unfortunate transaction ordering. One possible solution to mitigate this

   * race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards:

   * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729

   * @param _spender The address which will spend the funds.

   * @param _value The amount of tokens to be spent.

   */

  function approve(address _spender, uint256 _value) public returns (bool) {

    allowed[msg.sender][_spender] = _value;

    emit Approval(msg.sender, _spender, _value);

    return true;

  }

 

  /**

   * @dev Function to check the amount of tokens that an owner allowed to a spender.

   * @param _owner address The address which owns the funds.

   * @param _spender address The address which will spend the funds.

   * @return A uint256 specifying the amount of tokens still available for the spender.

   */

  function allowance(address _owner, address _spender) public view returns (uint256) {

    return allowed[_owner][_spender];

  }

 

  /**

   * @dev Increase the amount of tokens that an owner allowed to a spender.

   * approve should be called when allowed[_spender] == 0. To increment

   * allowed value is better to use this function to avoid 2 calls (and wait until

   * the first transaction is mined)

   * From MonolithDAO Token.sol

   * @param _spender The address which will spend the funds.

   * @param _addedValue The amount of tokens to increase the allowance by.

   */

  function increaseApproval(address _spender, uint256 _addedValue) public returns (bool) {

    allowed[msg.sender][_spender] = (allowed[msg.sender][_spender].add(_addedValue));

    emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);

    return true;

  }

 

  /**

   * @dev Decrease the amount of tokens that an owner allowed to a spender.

   * approve should be called when allowed[_spender] == 0. To decrement

   * allowed value is better to use this function to avoid 2 calls (and wait until

   * the first transaction is mined)

   * From MonolithDAO Token.sol

   * @param _spender The address which will spend the funds.

   * @param _subtractedValue The amount of tokens to decrease the allowance by.

   */

  function decreaseApproval(address _spender, uint256 _subtractedValue) public returns (bool) {

    uint256 oldValue = allowed[msg.sender][_spender];

    if (_subtractedValue > oldValue) {

      allowed[msg.sender][_spender] = 0;

    } else {

      allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);

    }

    emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);

    return true;

  }

 

}

 

/**

 * @title Ownable

 * @dev The Ownable contract has an owner address, and provides basic authorization control

 * functions, this simplifies the implementation of "user permissions".

 */

contract Ownable {

  address public owner;

 

 

  event OwnershipRenounced(address indexed previousOwner);

  event OwnershipTransferred(

    address indexed previousOwner,

    address indexed newOwner

  );

 

 

  /**

   * @dev The Ownable constructor sets the original `owner` of the contract to the sender

   * account.

   */

  constructor() public {

    owner = msg.sender;

  }

 

  /**

   * @dev Throws if called by any account other than the owner.

   */

  modifier onlyOwner() {

    require(msg.sender == owner);

    _;

  }

 

  /**

   * @dev Allows the current owner to relinquish control of the contract.

   * @notice Renouncing to ownership will leave the contract without an owner.

   * It will not be possible to call the functions with the `onlyOwner`

   * modifier anymore.

   */

  function renounceOwnership() public onlyOwner {

    emit OwnershipRenounced(owner);

    owner = address(0);

  }

 

  /**

   * @dev Allows the current owner to transfer control of the contract to a newOwner.

   * @param _newOwner The address to transfer ownership to.

   */

  function transferOwnership(address _newOwner) public onlyOwner {

    _transferOwnership(_newOwner);

  }

 

  /**

   * @dev Transfers control of the contract to a newOwner.

   * @param _newOwner The address to transfer ownership to.

   */

  function _transferOwnership(address _newOwner) internal {

    require(_newOwner != address(0));

    emit OwnershipTransferred(owner, _newOwner);

    owner = _newOwner;

  }

}

 

/**

 * @title Claimable

 * @dev Extension for the Ownable contract, where the ownership needs to be claimed.

 * This allows the new owner to accept the transfer.

 */

contract Claimable is Ownable {

  address public pendingOwner;

 

  /**

   * @dev Modifier throws if called by any account other than the pendingOwner.

   */

  modifier onlyPendingOwner() {

    require(msg.sender == pendingOwner);

    _;

  }

 

  /**

   * @dev Allows the current owner to set the pendingOwner address.

   * @param newOwner The address to transfer ownership to.

   */

  function transferOwnership(address newOwner) onlyOwner public {

    pendingOwner = newOwner;

  }

 

  /**

   * @dev Allows the pendingOwner address to finalize the transfer.

   */

  function claimOwnership() onlyPendingOwner public {

    emit OwnershipTransferred(owner, pendingOwner);

    owner = pendingOwner;

    pendingOwner = address(0);

  }

}

 

 

/**

 * @title Pausable

 * @dev Base contract which allows children to implement an emergency stop mechanism.

 */

contract Pausable is Ownable {

  event Pause();

  event Unpause();

 

  bool public paused = false;

 

  /**

   * @dev Modifier to make a function callable only when the contract is not paused.

   */

  modifier whenNotPaused() {

    require(!paused);

    _;

  }

 

  /**

   * @dev Modifier to make a function callable only when the contract is paused.

   */

  modifier whenPaused() {

    require(paused);

    _;

  }

 

  /**

   * @dev called by the owner to pause, triggers stopped state

   */

  function pause() onlyOwner whenNotPaused public {

    paused = true;

    emit Pause();

  }

 

  /**

   * @dev called by the owner to unpause, returns to normal state

   */

  function unpause() onlyOwner whenPaused public {

    paused = false;

    emit Unpause();

  }

}

 

/**

 * @title Upcoin

 * @dev The Upcoin ERC20 contract

 */

contract UniversalUSD is StandardToken, Pausable, Claimable {

 

  string public constant name = "UniversalUSD"; // solium-disable-line uppercase

  string public constant symbol = "UUSD"; // solium-disable-line uppercase

  uint8 public constant decimals = 18; // solium-disable-line uppercase

 

  uint256 public constant INITIAL_SUPPLY = 300000000 * (10 ** uint256(decimals));

 

  /**

   * @dev Constructor that gives msg.sender all of existing tokens.

   */

  constructor() public {

    totalSupply_ = INITIAL_SUPPLY;

    balances[msg.sender] = INITIAL_SUPPLY;

    emit Transfer(address(0), msg.sender, INITIAL_SUPPLY);

  }

  

  function transfer(address _to, uint256 _value) public whenNotPaused returns (bool) {

    return super.transfer(_to, _value);

  }

 

  function transferFrom(address _from, address _to, uint256 _value) public whenNotPaused returns (bool) {

    return super.transferFrom(_from, _to, _value);

  }

 

  function approve(address _spender, uint256 _value) public whenNotPaused returns (bool) {

    return super.approve(_spender, _value);

  }

 

  function increaseApproval(address _spender, uint _addedValue) public whenNotPaused returns (bool success) {

    return super.increaseApproval(_spender, _addedValue);

  }

 

  function decreaseApproval(address _spender, uint _subtractedValue) public whenNotPaused returns (bool success) {

    return super.decreaseApproval(_spender, _subtractedValue);

  }

 

  function mint(address _to, uint256 _value) public onlyOwner {

        require(_to != address(0), "to address cannot be zero");

        totalSupply_ = totalSupply_.add(_value);

        balances[_to] = balances[_to].add(_value);

    }

 

  function burn(uint256 _value) public {

      if (balances[msg.sender] >= _value) {

        balances[msg.sender] = balances[msg.sender].sub(_value);

        totalSupply_ = totalSupply_.sub(_value);

      }

  }

 

}

 

/**

 * @notes All the credits go to the fantastic OpenZeppelin project and its community

 * See https://github.com/OpenZeppelin/openzeppelin-solidity

 */