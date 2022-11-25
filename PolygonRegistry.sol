// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./IRoles.sol";

//upgrade
contract PolygonRegistry is
    Initializable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    /**
     * @notice Address of Roles contract that manage access control
     * @dev This contract is used to grant roles and restrict some calls and access
     */
    IRoles public roles;

    mapping(address => uint256) public balanceOf;

    /**
     * @dev Function with a require that allows access to a specific role
     */
    function _onlyDefaultAdmin() private view {
        require(
            roles.hasRole(roles.getHashRole("DEFAULT_ADMIN_ROLE"), msg.sender),
            "Error, default admin role"
        );
    }

    /**
     * @dev Modifier that calls a function that allows access to a specific role
     * Requirements:
     * - The msg.sender must have DEFAULT_ADMIN_ROLE role
     */
    modifier onlyDefaultAdmin() {
        _onlyDefaultAdmin();
        _;
    }

    //Event to sync balances from eth to polygon
    event BalanceUpdated(address indexed _address, uint256 indexed _balance);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _rolesContract) public initializer {
        __Pausable_init();
        __UUPSUpgradeable_init();

        roles = IRoles(_rolesContract);
    }

    function updateBalance(
        address _from,
        address _to,
        uint256 _balanceFrom,
        uint256 _balanceTo
    ) external {
        require(
            roles.hasRole(keccak256("RELAYER_ROLE"), msg.sender),
            "sender is not the Relayer"
        );
        if (_from != address(0)) {
            balanceOf[_from] = _balanceFrom;
            balanceOf[_to] = _balanceTo;
            emit BalanceUpdated(_from, _balanceFrom);
            emit BalanceUpdated(_to, _balanceTo);
        } else {
            balanceOf[_to] = _balanceTo;
            emit BalanceUpdated(_to, _balanceTo);
        }
    }

    function updateAddress(address _address, uint256 _newBalance) external {
        require(
            roles.hasRole(keccak256("RELAYER_ROLE"), msg.sender) ||
                roles.hasRole(
                    roles.getHashRole("DEFAULT_ADMIN_ROLE"),
                    msg.sender
                ),
            "sender is not the Relayer nor Admin"
        );

        balanceOf[_address] = _newBalance;
    }

    /**
     *
     * @dev SAuthorize the new implementation
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused.
     */

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyDefaultAdmin
        whenPaused
    {}

    /**
     *
     * @dev See {utils/UUPSUpgradeable-upgradeTo}.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused.
     *
     */

    function upgradeTo(address newImplementation)
        external
        override
        onlyDefaultAdmin
        whenPaused
    {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, new bytes(0), false);
    }

    /**
     *
     * @dev See {utils/UUPSUpgradeable-upgradeToAndCall}.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused.
     *
     */

    function upgradeToAndCall(address newImplementation, bytes memory data)
        external
        payable
        override
        onlyDefaultAdmin
        whenPaused
    {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data, true);
    }

    /**
     *
     * @dev See {security/PausableUpgradeable-_pause}.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     *
     */
    function pause() external whenNotPaused onlyDefaultAdmin {
        //Debería ser la misma persona la que deploya el contrato de roles y el de misteryBox
        _pause();
    }

    /**
     *
     * @dev See {security/PausableUpgradeable-_unpause}.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     *
     */
    function unpause() external whenPaused onlyDefaultAdmin {
        //Debería ser la misma persona la que deploya el contrato de roles y el de misteryBox
        _unpause();
    }
}
