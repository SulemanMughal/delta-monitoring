let teams_list = [
  {
    id: 1,
    text: "Team A",
    ip: "10.8.0.0",
    members: ["User_A", "User_B", "User_C"],
  },
  {
    id: 2,
    text: "Team B",
    ip: "192.168.2.0",
    members: ["User_D", "User_E", "User_F"],
  },
  {
    id: 3,
    text: "Team C",
    ip: "192.168.3.0",
    members: ["User_G", "User_H", "User_I"],
  },
  {
    id: 4,
    text: "Team D",
    ip: "192.168.4.0",
    members: ["User_G", "User_K", "User_L"],
  },
  {
    id: 5,
    text: "Team E",
    ip: "192.168.5.0",
    members: ["User_M", "User_N", "User_O"],
  },
  {
    id: 6,
    text: "Team F",
    ip: "192.168.6.0",
    members: ["User_P", "User_Q", "User_R"],
  },
  {
    id: 7,
    text: "Team G",
    ip: "192.168.7.0",
    members: ["User_S", "User_T", "User_U"],
  },
  {
    id: 8,
    text: "Team H",
    ip: "192.168.8.0",
    members: ["User_V", "User_W", "User_X"],
  },
];

let users_data = [
  {
    id : "1",
    text: "User_A",
    Team: "Team B",
    ip: "10.8.0.10",
  },
  {
    id : "2",
    text: "User_B",
    Team: "Team A",
    ip: "10.8.0.9",
  },
  {
    id : "3",
    text: "User_C",
    Team: "Team A",
    ip: "192.168.1.3",
  },
  {
    id : "4",
    text: "User_D",
    Team: "Team B",
    ip: "192.168.2.1",
  },
  {
    id : "5",
    text: "User_E",
    Team: "Team B",
    ip: "192.168.2.2",
  },
  {
    id : "6",
    text: "User_F",
    Team: "Team B",
    ip: "192.168.2.3",
  },
  {
    id : "7",
    text: "User_G",
    Team: "Team C",
    ip: "192.168.3.1",
  },
  {
    id : "8",
    text: "User_G",
    Team: "Team C",
    ip: "192.168.3.2",
  },
  {
    id : "9",
    text: "User_H",
    Team: "Team C",
    ip: "192.168.3.3",
  },
  
];

let challenges = [
  {
    id : "1",
    text: "Challenges A",
    Team: "Team A",
    ip: "192.168.0.151",
    port: "3000",
  },
  {
    id : "2",
    text: "Challenges B",
    Team: "Team A",
    ip: "192.168.1.150",
    port: "3001",
  },
  {
    id : "3",
    text: "Challenges C",
    Team: "Team A",
    ip: "192.168.1.152",
    port: "3002",
  },
  {
    id : "4",
    text: "Challenges A",
    Team: "Team B",
    ip: "192.168.2.151",
    port: "3000",
  },
  {
    id : "5",
    text: "Challenges B",
    Team: "Team B",
    ip: "192.168.2.152",
    port: "3001",
  },
  {
    id : "6",
    text: "Challenges C",
    Team: "Team B",
    ip: "192.168.2.153",
    port: "3002",
  },
];





// let src_ports= [
//   {
//     "id" : "1",
//     "text" : "80",
//   },
// ]


// generate teams z

// function generateTeams(numberOfTeams) {
//   let teamsList = [];

//   for (let i = 1; i <= numberOfTeams; i++) {
//       let team = {
//           id: i,
//           text: `Team ${String.fromCharCode(65 + (i - 1) % 26)}`,
//           ip: `192.168.${i % 256}.0`,
//           members: [
//               `User_${String.fromCharCode(65 + (i - 1) % 26)}`,
//               `User_${String.fromCharCode(66 + (i - 1) % 26)}`,
//               `User_${String.fromCharCode(67 + (i - 1) % 26)}`
//           ],
//       };

//       teamsList.push(team);
//   }

//   return teamsList;
// }

function generateTeams(numTeams) {
  let teamsList = [];

  // Function to generate unique user names
  function generateUniqueUser() {
      const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      return `User_${characters[Math.floor(Math.random() * characters.length)]}`;
  }

  // Function to generate teams
  for (let i = 1; i <= numTeams; i++) {
      let team = {
          id: i,
          text: `Team ${String.fromCharCode(65 + (i - 1) % 26)}`,
          ip: `10.8.${i % 256}.0`,
          members: [],
      };

      // Generate unique members for each team
      for (let j = 0; j < 3; j++) {
          let uniqueUser;
          do {
              uniqueUser = generateUniqueUser();
          } while (team.members.includes(uniqueUser));
          team.members.push(uniqueUser);
      }

      teamsList.push(team);
  }

  return teamsList;
}


function generateSrcPorts(count, startPort = 80, endPort = 65535) {
  const srcPorts = [];

  for (let i = 0; i < count; i++) {
    const port = Math.floor(Math.random() * (endPort - startPort + 1)) + startPort;
    srcPorts.push({ id: String(i + 1), text: String(port) });
  }

  return srcPorts;
}




function generateDstPorts(count, startPort = 80, endPort = 65535) {
  const dstPorts = [];

  for (let i = 0; i < count; i++) {
    const port = Math.floor(Math.random() * (endPort - startPort + 1)) + startPort;
    dstPorts.push({ id: String(i + 1), text: String(port) });
  }

  return dstPorts;
}