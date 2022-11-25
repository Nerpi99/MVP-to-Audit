// SPDX-License-Identifier: MIT
pragma solidity ^0.8.1;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "./IRoles.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

interface INft {
    function safeMint(
        address _to,
        string memory _uri,
        string memory _moralisId
    ) external returns (uint256);

    function cost() external view returns (uint256);

    function perceptionCollection() external returns (bool);

    function revealed() external returns (bool);

    //payable(ngoAddress)
    function ngoAddress() external returns (address);

    function feeNgoPercent() external returns (uint256);

    function lazyMint(address _to) external returns (uint256);

    function balanceOf(address owner) external returns (uint256);

    function startedPreSale() external returns (bool);

    function isEndedMvpSelling() external view returns (bool);
}

interface IMvp {
    function safeMint(
        address _to,
        string memory _uri,
        address _creator,
        string memory _moralisId
    ) external returns (uint256);

    function cost() external view returns (uint256);

    function perceptionCollection() external returns (bool);

    function revealed() external returns (bool);

    //payable(ngoAddress)
    function ngoAddress() external returns (address);

    function feeNgoPercent() external returns (uint256);

    function lazyMint(address _to) external returns (uint256);

    function balanceOf(address owner) external returns (uint256);
}

contract LazyMinting is
    Initializable,
    PausableUpgradeable,
    UUPSUpgradeable,
    EIP712Upgradeable,
    ReentrancyGuardUpgradeable
{
    struct Nft {
        string _uri;
        address _signer;
        string _timeStamp;
        INft _nftContract;
    }

    struct Params {
        address _rolesContract;
        address _priceFeed;
        address _collectorAddress;
        address _mvpAddress;
        uint256 _mvpDiscount;
    }

    /**
     * @notice Mapping from signature hash to boolean
     * @dev Indicate if the signature has already been used or not.
     */

    mapping(bytes => bool) private isMinted;

    /**
     * @notice Counts the amount of tokens claimed in total.
     * @dev This value increases every time a client buys or claims a token.
     */
    uint256 public tokensSold; // Cantidad de nfts vendidos hasta el momento

    /**
     * @notice Address of Roles contract that manage access control
     * @dev This contract is used to grant roles and restrict some calls and access
     * @return roles the address of the Roles contract
     */
    IRoles public roles;

    /**
     * @notice Oracle variable to check the price of MATIC
     * @dev Used to ask the MATIC price in usd and compute the value of a NFT
     */
    AggregatorV3Interface public priceFeed;
    //0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419 eth/usd aggregator

    //Contrato Mvp
    IMvp public mvpContract;

    //Wallet recaudadora del lazymint
    address public collectorAddress;

    //Descuento de mvp
    uint256 public mvpDiscount;

    //Evento que chequea si se realizó la ejecución de la funcion mediante un id de stripe
    mapping(string => bool) private stripeEventMinted;

    /**
     * @dev Function with a require that allows access to a specific role
     */
    function _onlyDefaultAdmin() private view {
        require(
            roles.hasRole(roles.getHashRole("DEFAULT_ADMIN_ROLE"), msg.sender),
            "Error, the account is not the default admin"
        );
    }

    function _not0Address(address _variable) private view {
        require(_variable != address(0));
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
            "Error, the account is not the default admin"
        );
    }

    /**
     * @dev Modifier that calls a function that allows access to a specific role
     * Requirements:
     *
     * - The msg.sender must have NFT_ADMIN_ROLE role
     */
    modifier onlyNftAdmin() {
        _onlyDefaultAdmin();
        _;
    }

    /**
     * @notice Event emitted every time a client buys or claims a token.
     * @dev It is used to sync with the frontend.
     * @param moralisId moralis Id in the database.
     * @param tokenId the token ID affected
     * @param tokenContract address of the collection
     * @param buyer address of the buyer
     */
    event eventBuyMvp(
        string moralisId,
        uint256 tokenId,
        address tokenContract,
        address buyer
    );

    event StripeMint(
        string moralisId,
        uint256 tokenId,
        address tokenContract,
        address buyer,
        string eventId
    );

    /**
     * @notice Event emitted every time a client buys or claims a token.
     * @dev It is used to sync with the frontend.
     * @param moralisId moralis Id in the database.
     * @param revealed Indicates if the metadata of the nft is revealed or not.
     */
    event eventMint(string moralisId, bool revealed, uint256 tokenId);

    event setNewCollector(address newColector);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    /*
     * @notice Function that intializes the Proxy contract.
     * @dev Initalize the initial state of the contract
     */
    function initialize(Params memory init) external initializer {
        __ReentrancyGuard_init();
        __EIP712_init("Lazy Mint", "2.0.0");
        __UUPSUpgradeable_init();
        roles = IRoles(init._rolesContract);
        priceFeed = AggregatorV3Interface(init._priceFeed);
        collectorAddress = init._collectorAddress;
        mvpContract = IMvp(init._mvpAddress);
        mvpDiscount = init._mvpDiscount;
    }

    function buyMvpPass() external payable whenNotPaused nonReentrant {
        require(
            roles.hasRole(keccak256("MVP_WHITELIST"), msg.sender),
            "Address not whitelisted"
        );

        uint256 cost = mvpContract.cost();
        require(msg.value >= cost, "Low msg.value");

        tokensSold++;

        uint256 _tokenId = mvpContract.lazyMint(msg.sender);
        collectorTransfer(msg.value);

        //Evento al comprar
        emit eventBuyMvp("", _tokenId, address(mvpContract), msg.sender);
    }

    function computeDiscountedAmount(address _nftAddress)
        public
        view
        returns (uint256)
    {
        //Checkear si el msg.sender tiene balance de mvpPass
        uint256 cost = computeAmount(_nftAddress);
        cost = (cost * (100 - mvpDiscount)) / 100;

        return cost;
    }

    /**
     * @notice Compute the price in matic of 1 NFT
     * @dev uses the state variable usdPrice with the price feed to compute the price of a NFT
     * @param _collectionAddress Address of the contract that the price is to be fetched
     * @return uint256 the price of a NFT in matic in weis
     */
    function computeAmount(address _collectionAddress)
        public
        view
        returns (uint256)
    {
        return ((INft(_collectionAddress).cost() * (10**8)) / getLatestPrice());
    }

    /// @notice Claims the token through lazy mint
    /// @dev See {ArtNft-safeMint} & see {LazyMinting-_verify}.
    /// @param _nftData: struct with the data
    /// @param signature:signature of the nft
    /// @param _moralisId: Database ID
    function redeem(
        Nft memory _nftData,
        bytes calldata signature,
        string memory _moralisId
    ) external payable whenNotPaused nonReentrant {
        uint256 cost;

        if (
            _nftData._nftContract.startedPreSale() &&
            !_nftData._nftContract.isEndedMvpSelling()
        ) {
            require(mvpContract.balanceOf(msg.sender) > 0, "No tiene mvp pass");
            cost = computeDiscountedAmount(address(_nftData._nftContract));
        } else {
            cost = computeAmount(address(_nftData._nftContract));
        }

        require(msg.value >= cost, "Insufficient funds");

        //Preguntar si la forma de reclamar nfts es igual que en polygon
        require(
            _verify(
                _nftData._signer,
                _hash(
                    _nftData._uri,
                    _nftData._signer,
                    address(_nftData._nftContract),
                    _nftData._timeStamp
                ),
                signature
            ),
            "Invalid signature"
        );

        require(!isMinted[signature], "This NFT was already minted");

        collectorTransfer(msg.value);

        uint256 tokenId = _nftData._nftContract.safeMint(
            msg.sender,
            _nftData._uri,
            _moralisId
        );

        isMinted[signature] = true;

        emit eventMint(_moralisId, _nftData._nftContract.revealed(), tokenId);
        // Si reveal === true => que use el eventMint como antes
        // else => que no haga nada con este evento
    }

    function collectorTransfer(uint256 _value) internal {
        (bool success, ) = collectorAddress.call{value: _value}("");
        require(success, "Transfer failed!");
    }

    /**
     * @dev See {draft-EIP712-_hashTypedDataV4}.
     */
    function _hash(
        string memory _uri,
        address _signer,
        address _nftContract,
        string memory _timeStamp
    ) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        keccak256(
                            "NFT(string _uri,address _signer,address _nftContract,string _timeStamp)"
                        ),
                        keccak256(bytes(_uri)),
                        _signer,
                        _nftContract,
                        keccak256(bytes(_timeStamp))
                    )
                )
            );
    }

    /**
     * @dev See {SignatureChecker-isValidSignatureNow}.
     */
    function _verify(
        address signer,
        bytes32 digest,
        bytes memory signature
    ) internal view returns (bool) {
        return SignatureChecker.isValidSignatureNow(signer, digest, signature);
    }

    /**
     * @notice Function to check the current matic price
     * @dev External call to the price feed, the return amount is represented in 8 decimals
     * @return Documents the price of 1 ETH in USD
     */
    function getLatestPrice() public view returns (uint256) {
        (
            ,
            /*uint80 roundID*/
            int256 price, /*uint startedAt*/ /*uint timeStamp*/ /*uint80 answeredInRound*/
            ,
            ,

        ) = priceFeed.latestRoundData();
        return uint256(price);
    }

    // SETTERS

    function setRoles(address _rolesContract)
        external
        onlyDefaultAdmin
        not0Address(_rolesContract)
    {
        roles = IRoles(_rolesContract);
    }

    function setPriceFeed(address _priceFeed)
        external
        onlyDefaultAdmin
        not0Address(_priceFeed)
    {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    function setCollector(address _collectorAddress)
        external
        onlyDefaultAdmin
        not0Address(_collectorAddress)
    {
        //Evento al cambiar el colector
        collectorAddress = _collectorAddress;
        emit setNewCollector(_collectorAddress);
    }

    function setMvpContract(address _newMvp)
        external
        onlyDefaultAdmin
        not0Address(_newMvp)
    {
        mvpContract = IMvp(_newMvp);
    }

    function setMvpDiscount(uint256 _newMvpDiscount) external onlyDefaultAdmin {
        mvpDiscount = _newMvpDiscount;
    }

    // GETTERS

    function getStripeEvent(string memory _eventId)
        external
        view
        returns (bool)
    {
        return stripeEventMinted[_eventId];
    }

    /**
     * @dev See {security/PausableUpgradeable-_pause}.
     * Requirements:
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused
     */
    function pause() external whenNotPaused onlyDefaultAdmin {
        //Debería ser la misma persona la que deploya el contrato de roles y el de misteryBox
        _pause();
    }

    /**
     * @dev See {security/PausableUpgradeable-_unpause}.
     * Requirements:
     * - The caller must have ``role``'s admin role.
     * - The contract must be unpaused
     */
    function unpause() external whenPaused onlyDefaultAdmin {
        //Debería ser la misma persona la que deploya el contrato de roles y el de misteryBox
        _unpause();
    }

    /**
     * @dev See {utils/UUPSUpgradeable-_authorizeUpgrade}.
     * Requirements:
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused
     */
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        whenPaused
        onlyDefaultAdmin
    {}

    /**
     * @dev See {utils/UUPSUpgradeable-upgradeTo}.
     * Requirements:
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused
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
     * @dev See {utils/UUPSUpgradeable-upgradeToAndCall}.
     * Requirements:
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused
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
