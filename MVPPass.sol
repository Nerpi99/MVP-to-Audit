// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/StringsUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/common/ERC2981Upgradeable.sol";
import "./IRoles.sol";

//todo: upgrade para agregar acceso al counter
contract MvpPass is
    Initializable,
    ERC721URIStorageUpgradeable,
    PausableUpgradeable,
    ERC2981Upgradeable,
    UUPSUpgradeable
{
    using StringsUpgradeable for uint256;

    struct Params {
        string _name;
        string _symbol;
        address _rolesContract;
        uint96 _royalty;
        uint256 _cost;
        bool _perceptionCollection;
        uint96 _maxAmounToMint;
        address _royaltyReceiver;
        string _baseURI;
    }

    using CountersUpgradeable for CountersUpgradeable.Counter;

    CountersUpgradeable.Counter private _tokenIdCounter;

    /**
     * @notice Address of Roles contract that manage access control
     * @dev This contract is used to grant roles and restrict some calls and access
     */
    IRoles public roles;

    /**
     * @notice Price of the tokens
     * @dev Used to check the price of the collection
     * @return The price of 1 token expressed in weis in USD
     */
    uint256 public cost;

    /**
     * @notice Maximum amount of token to mint
     * @dev Used to limit the number of ntfs in the contract
     * @return returns The max amount of nfts
     */
    uint256 public maxAmountToMint;

    /**
     * @notice Default URL for non revealed collection
     * @dev Should return an IPFS URL to be displayed in case the collection is not revealed.
     * @return Returns the default IPFS URL.
     */
    string public revealUrl;

    /**
     * @notice Reveals or not the tokenURI for the collection
     * @dev Used to check if the collection was revealed or not
     * @return Returns if the collection is revealed or not
     */
    bool public revealed;

    /**
     * @notice Royalty fee of the erc721 collection
     * @dev See {contracts-upgradeable - IERC2981Upgradeable}
     * @return returns the erc721 collection royalty fee. Example: 100 is 1%fee (100/100 = 1)
     */
    uint96 public royaltyFee;

    /// @notice Address to be paid royalties
    /// @dev Are awarded the fee corresponding to royaltyFee
    /// @return The Address
    address public royaltyReceiver;

    /**
     * @notice Collection created by Perception
     * @dev Used to check if the collection was created by perception
     * @return Returns if the collection is from perception
     */
    bool public perceptionCollection;

    //BaseUri para la concatenacion de ids
    string public baseURI;

    /**
     * @notice  Event emitted to register the token mint
     * @dev Event for saving info in the database
     * @param minterAddress Address to which the nft is minted
     * @param tokenId Id of the minted token
     * @param _moralisId Id used to identify the nft in the database
     * @param description description of the transaction
     */
    event eventMint(
        address indexed minterAddress,
        uint256 tokenId,
        string _moralisId,
        string description
    );

    event UpdatedBalance(
        address indexed from,
        address indexed to,
        uint256 tokenId,
        uint256 indexed balanceFrom,
        uint256 balanceTo
    );

    /**
     * @dev Function with a require that allows access to a specific role
     */
    function _onlyDefaultAdmin() private view {
        require(
            roles.hasRole(roles.getHashRole("DEFAULT_ADMIN_ROLE"), msg.sender),
            "Error, default admin role"
        );
    }

    function _not0Address(address _variable) private pure {
        require(_variable != address(0));
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

    modifier not0Address(address _variable) {
        _not0Address(_variable);
        _;
    }

    /**
     * @dev Function with a require that allows access to a specific role
     */
    function _onlyNftAdmin() private view {
        require(
            roles.hasRole(roles.getHashRole("NFT_ADMIN_ROLE"), msg.sender),
            "Error, nft admin role"
        );
    }

    /**
     * @dev Modifier that calls a function that allows access to a specific role
     * Requirements:
     * - The msg.sender must have NFT_ADMIN_ROLE role
     */
    modifier onlyNftAdmin() {
        _onlyNftAdmin();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(Params memory init) public initializer {
        __ERC721_init(init._name, init._symbol);
        __Pausable_init();
        __UUPSUpgradeable_init();
        _setDefaultRoyalty(init._royaltyReceiver, init._royalty);

        roles = IRoles(init._rolesContract);
        cost = init._cost;
        royaltyFee = init._royalty;
        perceptionCollection = init._perceptionCollection;
        royaltyReceiver = init._royaltyReceiver;
        maxAmountToMint = init._maxAmounToMint; //400 es el max de la coleccion
        baseURI = init._baseURI;
    }

    function _baseURI() internal view override returns (string memory) {
        //return "aqui va el uri de la carpeta de pinata";
        return baseURI;
    }

    //Funcion que mintea
    function lazyMint(address _to) external returns (uint256) {
        require(
            roles.hasRole(keccak256("LAZY_MINT_CONTRACT"), msg.sender) ||
                roles.hasRole(keccak256("MINTER_ROLE"), msg.sender),
            "Only allowed addresses can mint."
        );

        uint256 tokenId = _tokenIdCounter.current();
        require(tokenId < maxAmountToMint, "Limit amount of nfts reached");
        _tokenIdCounter.increment();

        _safeMint(_to, tokenId);

        emit eventMint(_to, tokenId, "", "Mint new MVP Pass");
        return tokenId;
    }

    function getTokenCounter() external view returns (uint256) {
        return _tokenIdCounter.current();
    }

    function setRoyalty(RoyaltyInfo memory _newRoyalty)
        external
        onlyNftAdmin
        whenNotPaused
    {
        _setDefaultRoyalty(_newRoyalty.receiver, _newRoyalty.royaltyFraction);
        royaltyFee = _newRoyalty.royaltyFraction;
        royaltyReceiver = _newRoyalty.receiver;
    }

    /**
     * @notice Function used to set the maximum tokens allowed to mint
     * @dev Sets the amount of nfts that the collection can have
     * @param _max Maximum amount of token in the collection
     * Requirements:
     *
     * - The caller must have ``role``'s nft admin role.
     * - The contract must not be paused
     *
     */
    function setmaxAmountToMint(uint256 _max)
        external
        onlyNftAdmin
        whenNotPaused
    {
        maxAmountToMint = _max;
    }

    /**
     * @notice Function used to set the cost in usd of the token
     * @dev Sets a new cost
     * @param _newcost Price of the tokens
     * Requirements:
     *
     * - The caller must have ``role``'s nft admin role.
     * - The _newcost variable must be set to weis
     */
    function setCost(uint256 _newcost) external onlyNftAdmin whenNotPaused {
        cost = _newcost;
    }

    function setRoles(address _newRoles)
        external
        onlyNftAdmin
        not0Address(_newRoles)
    {
        roles = IRoles(_newRoles);
    }

    function setBaseURI(string memory _newBaseURI) external onlyNftAdmin {
        baseURI = _newBaseURI;
    }

    function setRevealUrl(string memory _revealUrl) external onlyNftAdmin {
        revealUrl = _revealUrl;
    }

    /**
     * @dev See {ERC721URIStorage-tokenURI}.
     */
    function tokenURI(uint256 tokenId)
        public
        view
        virtual
        override
        returns (string memory)
    {
        require(_exists(tokenId), "ERC721: invalid token ID");

        string memory currentBaseURI = _baseURI();

        if (revealed == true) {
            return
                bytes(currentBaseURI).length > 0
                    ? string(
                        abi.encodePacked(
                            currentBaseURI,
                            tokenId.toString(),
                            ".json"
                        )
                    )
                    : "";
        } else {
            return revealUrl;
        }
    }

    /**
     * @notice Function used to set if the collection is going to be reveal or not
     * @dev Sets the status of revealed.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s nft default admin.
     *
     */
    function revealCollection() public onlyDefaultAdmin {
        require(!revealed, "This collection is already revealed");
        revealed = true;
    }

    /**
     *
     * @dev See {security/PausableUpgradeable-_pause}.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must not be paused
     */
    function pause() external onlyDefaultAdmin {
        _pause();
    }

    /**
     *
     * @dev See {security/PausableUpgradeable-_unpause}.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused
     *
     */
    function unpause() external onlyDefaultAdmin {
        //Debería ser la misma persona la que deploya el contrato de roles y el de misteryBox
        _unpause();
    }

    /**
     * @dev See {ERC721-_beforeTokenTransfer}.
     * Requirements:
     *
     * - The contract must be not paused
     * - The wallet to which the token is going to be transferred must have less than the maximum allowed
     * - The wallet to which the token is going to be transferred must not be the address 0
     */

    // TODO: le sace el batchSize porque sino me rompia cuando compilaba en remix
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId,
        uint256 batchSize
    ) internal virtual override {
        require(!paused(), "ERC721Pausable: token transfer while paused");
        require(address(0) != to, "Can't transfer to the address 0");
        super._beforeTokenTransfer(from, to, tokenId, 0);
    }

    function _afterTokenTransfer(
        address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize
    ) internal virtual override {
        uint256 balanceFrom = 0;
        uint256 balanceTo = 0;
        if (from != address(0)) {
            balanceFrom = super.balanceOf(from);
        }

        if (to != address(0)) {
            balanceTo = super.balanceOf(to);
        }
        emit UpdatedBalance(from, to, firstTokenId, balanceFrom, balanceTo);
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
     * @dev See {IERC165-supportsInterface}.
     */

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC721Upgradeable, ERC2981Upgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
