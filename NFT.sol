// SPDX-License-Identifier: MIT
pragma solidity ^0.8.1;

import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/common/ERC2981Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./IRoles.sol";

contract ArtNft is
    Initializable,
    UUPSUpgradeable,
    ERC721URIStorageUpgradeable,
    ERC2981Upgradeable,
    PausableUpgradeable
{
    using CountersUpgradeable for CountersUpgradeable.Counter;

    /**
     * @notice Struct containing the parameters to initialize the collection
     */
    struct Params {
        string _name;
        string _symbol;
        string _contractUri;
        address _rolesContract;
        uint96 _royalty;
        uint256 _cost;
        bool _perceptionCollection;
        uint96 _maxNftsPerWallet;
        bool _revealed;
        string _revealUrl;
        address _ngoAddress;
        uint256 _feeNgoPercent;
        address _royaltyReceiver;
    }

    /**
     * @notice Contract that provides counters that can only be incremented, decremented or reset.
     * @dev This can be used e.g. to track the number of elements in a mapping, issuing ERC721 ids,
     * or counting request ids.
     * Include with `using Counters for Counters.Counter;`
     */
    CountersUpgradeable.Counter private _tokenIdCounter;

    /**
     * @notice Address of Roles contract that manage access control
     * @dev This contract is used to grant roles and restrict some calls and access
     */
    IRoles private roles;

    /**
     * @notice Standard used by opensea to display the nft
     * @dev This IPFS URL should return a JSON blob of data with the metadata for the token
     * @return returns a URL for the storefront-level metadata for the contract. (The royalty in the contractURI is divided by 100, 100 = 1% of fee)
     */
    string public contractURI;

    /**
     * @notice Royalty fee of the erc721 collection
     * @dev See {contracts-upgradeable - IERC2981Upgradeable}
     * @return returns the erc721 collection royalty fee. Example: 100 is 1%fee (100/100 = 1)
     */
    uint96 public royaltyFee;

    /**
     * @notice Maximum amount of token per wallet
     * @dev Used to limit the number of ntfs per user
     * @return returns The nft limit per wallet
     */
    uint256 public maxNftsPerWallet;

    /**
     * @notice Price of the tokens
     * @dev Used to check the price of the collection
     * @return The price of 1 token expressed in weis
     */
    uint256 public cost;

    /**
     * @notice Reveals or not the tokenURI for the collection
     * @dev Used to check if the collection was revealed or not
     * @return Returns if the collection is revealed or not
     */
    bool public revealed;

    /**
     * @notice Collection created by Perception
     * @dev Used to check if the collection was created by perception
     * @return Returns if the collection is from perception
     */
    bool public perceptionCollection;

    /**
     * @notice Default URL for non revealed collection
     * @dev Should return an IPFS URL to be displayed in case the collection is not revealed.
     * @return Returns the default IPFS URL.
     */
    string public revealUrl;

    /// @notice NGO account to which the fee is granted.
    /// @dev Are awarded the fee corresponding to feeNgoPercent
    /// @return The address of the NGO
    address payable public ngoAddress;

    //Porcentaje del fee que se le otorga a la ong
    //Este porcentaje corresponde al valor de cada nft y se otorga únicamente
    //a la hora de mintear el nft

    /// @notice Percentage of the fee granted to the NGO
    /// @dev This percentage corresponds to the value of each nft and is granted only at the time of minting the nft
    /// @return The Percentage of the fee
    uint256 public feeNgoPercent;

    /// @notice Address to be paid royalties
    /// @dev Are awarded the fee corresponding to royaltyFee
    /// @return The Address
    address public royaltyReceiver;

    bool public startedPreSale;

    uint256 public endPresaleAt;

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

    /**
     * @notice  Event emitted to register new cost in the collection
     * @dev Event for saving info in the database
     * @param newCost Cost of 1 token expressed in weis
     */
    event eventChangeCost(uint256 newCost);

    /**
     * @notice  Event emitted to register that the collection was revealed
     * @dev Event for saving info in the database
     */
    event eventRevealCollection();

    event StartMvpSelling();

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
     *
     * - The msg.sender must have DEFAULT_ADMIN_ROLE role
     */
    modifier onlyDefaultAdmin() {
        _onlyDefaultAdmin();
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
     *
     * - The msg.sender must have NFT_ADMIN_ROLE role
     */
    modifier onlyNftAdmin() {
        _onlyNftAdmin();
        _;
    }

    /**
     * @dev Function with a require that allows access to a specific role
     */
    function _onlyNftAdminMisteryBox() private view {
        require(
            roles.hasRole(roles.getHashRole("NFT_ADMIN_ROLE"), msg.sender) ||
                roles.hasRole(
                    roles.getHashRole("MISTERY_BOX_ADDRESS"),
                    msg.sender
                ),
            "Error, nft admin role"
        );
    }

    /**
     * @dev Modifier that calls a function that allows access to a specific role
     * Requirements:
     *
     * - The msg.sender must have NFT_ADMIN_ROLE role or MISTERY_BOX_ADDRESS role
     */
    modifier onlyNftAdminMisteryBox() {
        _onlyNftAdminMisteryBox();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    /**
     * @notice Function to initialize the Proxy Contract
     * @dev Initalize the initial state of the contract
     * @param init Struct containing the parameters to initialize the contract
     */

    function initialize(Params memory init) external initializer {
        require(init._rolesContract != address(0));
        __ERC721_init(init._name, init._symbol);
        __UUPSUpgradeable_init();
        __ERC2981_init();
        __ERC721URIStorage_init();
        __Pausable_init();
        _setDefaultRoyalty(init._royaltyReceiver, init._royalty);
        roles = IRoles(init._rolesContract);
        contractURI = init._contractUri;
        maxNftsPerWallet = init._maxNftsPerWallet;
        cost = init._cost;
        revealed = init._revealed;
        perceptionCollection = init._perceptionCollection;
        revealUrl = init._revealUrl;
        ngoAddress = payable(init._ngoAddress);
        feeNgoPercent = init._feeNgoPercent;
        royaltyFee = init._royalty;
        royaltyReceiver = init._royaltyReceiver;
    }

    function getTokenCounter() external view returns (uint256) {
        return _tokenIdCounter.current();
    }

    /**
     * @notice Function used to mint just 1 token
     * @dev See {ERC721/ERC721-_safeMint}.
     * @param _to Address to which the token is going to be minted
     * @param _uri IPFS URL with the metadata for the token
     * @param _moralisId Id used to identify the nft in the database
     * Requirements:
     *
     * - The wallet to which the token is going to be minted must have less than the maximum allowed
     * - The msg.sender must have MISTERY_BOX_ADDRESS role
     */

    function safeMint(
        address _to,
        string memory _uri,
        string memory _moralisId //27/4
    ) external whenNotPaused returns (uint256) {
        require(
            balanceOf(_to) < maxNftsPerWallet,
            "Can't mint more nfts in this wallet"
        );
        //Crear el rol antes de llamar a esta función
        require(
            roles.hasRole(
                roles.getHashRole("MISTERY_BOX_ADDRESS"),
                msg.sender
            ) || roles.hasRole(roles.getHashRole("MINTER_ROLE"), msg.sender),
            "Only allowed addresses can mint."
        );

        uint256 tokenId = _tokenIdCounter.current();
        _tokenIdCounter.increment();
        _safeMint(_to, tokenId);
        _setTokenURI(tokenId, _uri);
        emit eventMint(_to, tokenId, _moralisId, "Mint new NFT");
        return tokenId;
    }

    /* Nueva funcion para el minteo masivo
        - se manda el tokenId por parametro
        - hace que el tokenId autoincremental tome el valor ingresado por parametro + 1 
        - todo el resto de la funcion queda igual 
    */
    function safeBatchMint(
        address _to,
        string memory _uri,
        string memory _moralisId,
        uint256 _tokenId
    ) external whenNotPaused returns (uint256) {
        require(
            balanceOf(_to) < maxNftsPerWallet,
            "Can't mint more nfts in this wallet"
        );

        require(
            roles.hasRole(roles.getHashRole("MISTERY_BOX_ADDRESS"), msg.sender),
            "Only mistery box contract can call redeem"
        );

        _tokenIdCounter._value = _tokenId;
        _tokenIdCounter.increment();
        _safeMint(_to, _tokenId);
        _setTokenURI(_tokenId, _uri);
        emit eventMint(_to, _tokenId, _moralisId, "Mint new NFT");
        return _tokenId;
    }

    //En el contrato de colecciones
    function startMvpSelling(uint256 time) external onlyNftAdmin whenNotPaused {
        require(!startedPreSale, "Mvp presale started");

        startedPreSale = true;
        endPresaleAt = time;
        emit StartMvpSelling();
    }

    function isEndedMvpSelling() external view whenNotPaused returns (bool) {
        return !startedPreSale || block.timestamp >= endPresaleAt;
    }

    function setNgo(address _ngoAddress, uint256 _feeNgoPercent)
        external
        onlyNftAdmin
    {
        require(_feeNgoPercent <= 10000, "Wrong ngo percentage entered");
        ngoAddress = payable(_ngoAddress);
        feeNgoPercent = _feeNgoPercent;
    }

    /// @notice Set the new NGO address
    /// @dev Pass an address that is the new ngo account
    /// @param _ngoAddress: Is the new NGO address
    function setNgoAddress(address _ngoAddress) external onlyNftAdmin {
        ngoAddress = payable(_ngoAddress);
    }

    /// @notice Set the fee for the ngo
    /// @dev Pass an uint256 that is the new fee
    /// @param _feeNgoPercent: Is the new fee
    function setfeeNgoPercent(uint256 _feeNgoPercent) external onlyNftAdmin {
        require(_feeNgoPercent <= 10000, "Wrong ngo percentage entered");
        feeNgoPercent = _feeNgoPercent;
    }

    /**
     * @notice Function used to set the maximum tokens allowed per wallet
     * @dev Sets the amount of nfts a wallet can have
     * @param _max Maximum amount of token per wallet
     * Requirements:
     *
     * - The caller must have ``role``'s nft admin role.
     * - The contract must not be paused
     *
     */
    function setMaxNftsPerWallet(uint256 _max)
        external
        onlyNftAdmin
        whenNotPaused
    {
        maxNftsPerWallet = _max;
    }

    /**
     * @notice Function used to set the contractURI
     * @dev Sets the contractURI used in the contract
     * @param _contractURI IPFS URL used by the standard of opensea
     * Requirements:
     *
     * - The caller must have ``role``'s nft admin role.
     * - The contract must not be paused
     *
     */
    function setContractURI(string memory _contractURI)
        external
        onlyNftAdmin
        whenNotPaused
    {
        contractURI = _contractURI;
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
     * @notice Function used to set the royalties
     * @dev Sets the royalties for each nft created
     * @param _fee Royalty fee of the collection
     * Requirements:
     *
     * - The caller must have ``role``'s nft admin role.
     * - The contract must not be paused
     *
     */
    function setRoyaltyFee(uint96 _fee) external onlyNftAdmin whenNotPaused {
        require(
            _fee <= _feeDenominator(),
            "ERC2981: royalty fee will exceed salePrice"
        );
        royaltyFee = _fee;
        _setDefaultRoyalty(royaltyReceiver, _fee);
    }

    function setRoyaltyReceiver(address _royaltyReceiver)
        external
        onlyNftAdmin
        whenNotPaused
    {
        royaltyReceiver = _royaltyReceiver;
        _setDefaultRoyalty(_royaltyReceiver, royaltyFee);
    }

    /**
     * @notice Function used to set the cost of the token
     * @dev Sets a new cost
     * @param _newcost Price of the tokens
     * Requirements:
     *
     * - The caller must have ``role``'s nft admin role.
     * - The _newcost variable must be set to weis
     */
    function setCost(uint256 _newcost) external onlyNftAdmin whenNotPaused {
        cost = _newcost;
        emit eventChangeCost(_newcost);
    }

    function setRevealUrl(string memory _newRevealUrl)
        external
        onlyNftAdmin
        whenNotPaused
    {
        revealUrl = _newRevealUrl;
    }

    function getEndPresaleAt() public view returns (uint256) {
        return endPresaleAt;
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
        if (revealed == true) {
            return super.tokenURI(tokenId);
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
    function revealCollection() public onlyNftAdmin {
        require(!revealed, "This collection is already revealed");
        revealed = true;
        emit eventRevealCollection();
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
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId,
        uint256 batchSize
    ) internal virtual override {
        require(!paused(), "ERC721Pausable: token transfer while paused");
        require(
            balanceOf(to) < maxNftsPerWallet,
            "Can't send more nfts to this wallet"
        );
        require(address(0) != to, "Can't transfer to the address 0");
        super._beforeTokenTransfer(from, to, tokenId, 0);
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
}
