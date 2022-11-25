// SPDX-License-Identifier: MIT
pragma solidity ^0.8.1;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "hardhat/console.sol";

contract Roles is
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    PausableUpgradeable
{
    //Convert the string (a role) into a hash for a better flexibility
    mapping(string => bytes32) private roles;

    event CollectorChanged(
        address indexed previousCollector,
        address indexed newCollector,
        address msgSender
    );

    event eventMvpWhitelist(address indexed _address, string _action);
    event eventMvpWhitelistBatch(address[] indexed _addresses, string _action);

    // Is the address that will collect the funds of the differents contracts
    address private collector;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    function initialize(address _collector) external initializer {
        require(
            _collector != address(0),
            "The address cannot be the address 0"
        );
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();
        collector = _collector;

        //Roles
        roles["NFT_ADMIN_ROLE"] = keccak256("NFT_ADMIN_ROLE");
        roles["ARTIST_ROLE"] = keccak256("ARTIST_ROLE");
        roles["MVP_WHITELIST"] = keccak256("MVP_WHITELIST");
        roles["MINTER_ROLE"] = keccak256("MINTER_ROLE");
        roles["MISTERY_BOX_ADDRESS"] = keccak256("MISTERY_BOX_ADDRESS");

        // Contracts
        roles["LAZY_MINT_CONTRACT"] = keccak256("LAZY_MINT_CONTRACT");

        _setupRole(roles["NFT_ADMIN_ROLE"], msg.sender);
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must not be paused.
     *
     */
    function grantRole(bytes32 role, address account)
        public
        virtual
        override
        whenNotPaused
    {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender) ||
                hasRole(roles["NFT_ADMIN_ROLE"], msg.sender),
            "error in grant role"
        );

        if (
            role == getHashRole("NFT_ADMIN_ROLE") || role == DEFAULT_ADMIN_ROLE
        ) {
            require(
                hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
                "Only Default admin can grant NFT Admin role or Airdrop role"
            );
        }

        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must not be paused.
     */
    function revokeRole(bytes32 role, address account)
        public
        virtual
        override
        whenNotPaused
    {
        require(role != DEFAULT_ADMIN_ROLE, "Can't revoke default admin role");
        require(
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender) ||
                hasRole(roles["NFT_ADMIN_ROLE"], msg.sender),
            "error in revoke role"
        );

        if (hasRole(role, msg.sender) == hasRole(role, account)) {
            require(
                hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
                "Can't revoke same role"
            );
        }

        _revokeRole(role, account);
    }

    /**
     *
     * @dev Create the hash of the string sent by parameter
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must not be paused.
     *
     */
    function createRole(string memory _roleName)
        external
        whenNotPaused
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        roles[_roleName] = keccak256(abi.encodePacked(_roleName));
    }

    /**
     *
     * @dev Get the hash of the string sent by parameter
     *
     * The role must be previously included previously the mapping `roles`
     *
     * To add a role in the mapping, use {createRole}.
     *
     */
    function getHashRole(string memory _roleName)
        public
        view
        returns (bytes32)
    {
        return roles[_roleName];
    }

    /**
     *
     * @dev Get the collector address
     *
     */
    function getCollector() external view returns (address) {
        return collector;
    }

    /**
     *
     * @dev Set the collector address
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     */
    function setCollector(address _collector)
        external
        whenPaused
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(_collector != address(0));
        emit CollectorChanged(collector, _collector, msg.sender);
        collector = _collector;
    }

    /**
     *
     * @dev Add an account to the mvp whitelsit
     *
     * Requirements:
     *
     * - The caller must have ``role``'s LazyMint Role.
     * - The contract must not be paused.
     *
     */
    function addMvpWhitelist(address _address) external whenNotPaused {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender) ||
                hasRole(roles["NFT_ADMIN_ROLE"], msg.sender),
            "Error in add mvp whitelist : admin role"
        );
        if (!hasRole(roles["MVP_WHITELIST"], _address)) {
            emit eventMvpWhitelist(_address, "Add account to MVP Whitelist");
            _grantRole(roles["MVP_WHITELIST"], _address);
        }
    }

    function addMvpWhitelistBatch(address[] memory _addresses)
        external
        whenNotPaused
    {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender) ||
                hasRole(roles["NFT_ADMIN_ROLE"], msg.sender),
            "Error in add mvp whitelist batch : admin role"
        );

        uint256 length = _addresses.length;
        uint256 i = 0;

        while (i < length) {
            address addressInPosition = _addresses[i];

            if (!hasRole(roles["MVP_WHITELIST"], addressInPosition)) {
                emit eventMvpWhitelist(
                    addressInPosition,
                    "Add account to MVP Whitelist"
                );
                _grantRole(roles["MVP_WHITELIST"], addressInPosition);
            }

            i++;
        }
        emit eventMvpWhitelistBatch(
            _addresses,
            "Add addresses to MVP Whitelist"
        );
    }

    /**
     *
     * @dev remove an account of the presale sale
     *
     * Requirements:
     *
     * - The caller must have ``role``'s LazyMint role.
     * - The contract must not be paused.
     *
     */
    function removeMvpWhitelist(address _address) external whenNotPaused {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender) ||
                hasRole(roles["LAZY_MINT_CONTRACT"], msg.sender),
            "Error, the address does not have an Admin role Or Lazy Mint contract"
        );

        _revokeRole(getHashRole("MVP_WHITELIST"), _address);
        emit eventMvpWhitelist(_address, "remove account from MVP Whitelist");
    }

    /**
     *
     * @dev See {utils/UUPSUpgradeable-_authorizeUpgrade}.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     *
     */
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(DEFAULT_ADMIN_ROLE)
        whenPaused
    {}

    /**
     *
     * @dev See {utils/UUPSUpgradeable-upgradeTo}.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused
     *
     */
    function upgradeTo(address newImplementation)
        external
        override
        onlyRole(DEFAULT_ADMIN_ROLE)
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
     * - The contract must be paused
     *
     */
    function upgradeToAndCall(address newImplementation, bytes memory data)
        external
        payable
        override
        onlyRole(DEFAULT_ADMIN_ROLE)
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
    function pause() external whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
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
    function unpause() external whenPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        //Debería ser la misma persona la que deploya el contrato de roles y el de misteryBox
        _unpause();
    }
}
