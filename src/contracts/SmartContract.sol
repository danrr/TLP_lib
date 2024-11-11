// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract SmartContract {

    struct PuzzlePart {
        uint coin;
        uint upperBound;
        bytes commitment;
        bytes solution;
        bool paidOut;
    }

    enum Status { Setup, SettingCommitments, Solving }

    modifier onlyHelper() {
        require(msg.sender == helperID, "Only the helper can call this function.");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can call this function.");
        _;
    }

    address public helperID;
    uint public startTime;
    Status public contractStatus = Status.Setup;

    mapping(uint => PuzzlePart) public puzzleParts;
    uint public amountOfPuzzleParts;
    uint public nextUnsolvedPuzzlePart = 0;
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function initialize(
        uint[] memory _coins,
        uint[] memory _upperBounds,
        address _helperID
    ) public payable onlyOwner {

        require(_coins.length == _upperBounds.length, "The length of the coins and upperBounds arrays should be the same.");
        require(_coins.length > 0, "The length of the coins array should be greater than 0.");
        require(_helperID != address(0), "The helper ID should not be the zero address.");
        require(contractStatus == Status.Setup, "Contract setup is already completed.");

        if (amountOfPuzzleParts == 0) {
            helperID = _helperID;
            owner = msg.sender;
        }

        uint receivedValue = msg.value;
        uint startIndex = amountOfPuzzleParts;

        for (uint i = 0; i < _coins.length; i++) {
            puzzleParts[startIndex + i] = PuzzlePart({
                coin: _coins[i],
                upperBound: _upperBounds[i],
                commitment: "",
                solution: "",
                paidOut: false
            });
            receivedValue -= _coins[i];
        }

        require(receivedValue == 0, "The total value sent should be equal to the sum of the coins.");

        amountOfPuzzleParts += _coins.length;
    }


    function commitments() public view returns (bytes[] memory) {
        bytes[] memory commitments = new bytes[](amountOfPuzzleParts);
        for (uint i = 0; i < amountOfPuzzleParts; i++) {
            commitments[i] = puzzleParts[i].commitment;
        }
        return commitments;
    }

    function setCommitments(bytes[] calldata _commitments, uint startIndex) public onlyHelper {
        // Change status to SettingCommitments on the first call
        // And start the timer for the puzzles
        if (contractStatus == Status.Setup) {
            contractStatus = Status.SettingCommitments;
            startTime = block.timestamp;
        }

        require(contractStatus == Status.SettingCommitments, "Contract is not in SettingCommitments status.");
        require(startIndex + _commitments.length <= amountOfPuzzleParts, "Commitments exceed the number of puzzle parts.");

        // Check that the value at startIndex-1 is not 0 unless startIndex is 0
        if (startIndex > 0) {
            require(bytes(puzzleParts[startIndex - 1].commitment).length != 0, "Previous puzzle part commitment must be set.");
        }

        for (uint i = 0; i < _commitments.length; i++) {
            uint index = startIndex + i;
            require(index < amountOfPuzzleParts, "Index out of bounds.");
            require(bytes(puzzleParts[index].commitment).length == 0, "Commitment has already been set.");
            puzzleParts[index].commitment = _commitments[i];
        }

        // Check if all commitments have been set
        if (startIndex + _commitments.length == amountOfPuzzleParts) {
            contractStatus = Status.Solving;
        }
    }

    function registerSolution(bytes calldata solution, bytes calldata witness) public {
        require(contractStatus == Status.Solving, "Contract is not in Solving status.");
        require(nextUnsolvedPuzzlePart < amountOfPuzzleParts, "All puzzle parts have already been solved.");

        // If the solution is correct, the solver should be paid
        if (verifySolution(nextUnsolvedPuzzlePart, solution, witness,block.timestamp)) {
            puzzleParts[nextUnsolvedPuzzlePart].solution = solution;
            pay(nextUnsolvedPuzzlePart, msg.sender);
        } else {
            payBack(nextUnsolvedPuzzlePart);
        }

        nextUnsolvedPuzzlePart++;
    }

    function coins() public view returns (uint[] memory) {
        uint[] memory coins = new uint[](amountOfPuzzleParts);
        for (uint i = 0; i < amountOfPuzzleParts; i++) {
            coins[i] = puzzleParts[i].coin;
        }
        return coins;
    }

    function upperBounds() public view returns (uint[] memory) {
        uint[] memory upperBounds = new uint[](amountOfPuzzleParts);
        for (uint i = 0; i < amountOfPuzzleParts; i++) {
            upperBounds[i] = puzzleParts[i].upperBound;
        }
        return upperBounds;
    }

    function getCommitmentAt(uint puzzlePartIndex) public view returns (bytes memory) {
        require(puzzlePartIndex < amountOfPuzzleParts, "The puzzle part index is out of bounds.");
        require(puzzleParts[puzzlePartIndex].commitment.length > 0, "The commitment is not set yet.");
        return puzzleParts[puzzlePartIndex].commitment;
    }

    function getSolutionAt(uint puzzlePartIndex) public returns (bytes memory) {
        require(puzzlePartIndex < amountOfPuzzleParts, "The puzzle part index is out of bounds.");

        bytes memory solutionMemory = puzzleParts[puzzlePartIndex].solution;

        return solutionMemory;
    }

    function getUpperBoundAt(uint puzzlePartIndex) public view returns (uint) {
        require(puzzlePartIndex < amountOfPuzzleParts, "The puzzle part index is out of bounds.");
        return puzzleParts[puzzlePartIndex].upperBound;
    }

    function solutions() public view returns (bytes[] memory) {
        bytes[] memory solutions = new bytes[](amountOfPuzzleParts);
        for (uint i = 0; i < amountOfPuzzleParts; i++) {
            solutions[i] = puzzleParts[i].solution;
        }
        return solutions;
    }

    function pay(uint puzzlePartIndex, address solver) internal {
        require(!puzzleParts[puzzlePartIndex].paidOut, "The puzzle part has already been paid out.");
        puzzleParts[puzzlePartIndex].paidOut = true;
        payable(solver).transfer(puzzleParts[puzzlePartIndex].coin);
    }

    function payBack(uint puzzlePartIndex) public onlyOwner {
        require(!puzzleParts[puzzlePartIndex].paidOut, "The puzzle part has already been paid out.");
        puzzleParts[puzzlePartIndex].paidOut = true;
        payable(owner).transfer(address(this).balance);
    }

    function verifySolution(uint256 i, bytes calldata solution, bytes calldata witness, uint256 time) public view returns (bool) {
        uint256 upperBound = puzzleParts[i].upperBound;
        bool onTime = time <= startTime + upperBound;


        bytes memory concatenated = abi.encodePacked(solution, witness);
        bytes32 hash = keccak256(concatenated);


        bool correct = hash == abi.decode(puzzleParts[i].commitment, (bytes32));
        return onTime && correct;
    }
}

