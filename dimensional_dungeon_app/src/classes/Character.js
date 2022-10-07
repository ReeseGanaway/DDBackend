export class Character {
  step = 0;
  waiting = false;

  constructor(id, name, spriteSheet, icon, moveRange, dir, position, used) {
    this.id = id;
    this.name = name;
    this.spriteSheet = new Image();
    this.spriteSheet.src = spriteSheet;
    this.icon = icon;
    this.moveRange = moveRange;
    this.dir = dir;
    this.position = position;
    this.previousPosition = { ...position };
    this.used = used;
  }

  draw() {
    if (!this.spriteSheet.complete) {
      this.spriteSheet.onload = () => {
        this.checkDirection();
      };
    } else {
      this.checkDirection();
    }
  }

  checkDirection() {
    let canvas = document.getElementById("canvas");
    let context = canvas.getContext("2d");

    switch (this.dir) {
      case "down":
        if (this.step > 0 && this.step < 24) {
          context.drawImage(
            this.spriteSheet,
            0,
            0,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        } else if (this.step >= 24 && this.step < 48) {
          context.drawImage(
            this.spriteSheet,
            96,
            0,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        } else if (this.step === 0) {
          context.drawImage(
            this.spriteSheet,
            48,
            0,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        }
        break;
      case "up":
        if (this.step > 0 && this.step < 24) {
          context.drawImage(
            this.spriteSheet,
            0,
            144,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        } else if (this.step >= 24 && this.step < 48) {
          context.drawImage(
            this.spriteSheet,
            96,
            144,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        } else if (this.step === 0) {
          context.drawImage(
            this.spriteSheet,
            48,
            144,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        }
        break;
      case "left":
        if (this.step > 0 && this.step < 24) {
          context.drawImage(
            this.spriteSheet,
            0,
            48,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        } else if (this.step >= 24 && this.step < 48) {
          context.drawImage(
            this.spriteSheet,
            96,
            48,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        } else if (this.step === 0) {
          context.drawImage(
            this.spriteSheet,
            48,
            48,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        }
        break;
      case "right":
        if (this.step > 0 && this.step < 24) {
          context.drawImage(
            this.spriteSheet,
            0,
            96,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        } else if (this.step >= 24 && this.step < 48) {
          context.drawImage(
            this.spriteSheet,
            96,
            96,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        } else if (this.step === 0) {
          context.drawImage(
            this.spriteSheet,
            48,
            96,
            48,
            48,
            this.position.x,
            this.position.y,
            48,
            48
          );
        }
        break;
    }
  }

  //update the characters current position
  updatePos(newX, newY) {
    console.log(newX, newY);
    this.position.x = newX;
    this.position.y = newY;
    if (this.step === 47) {
      this.step = 0;
    } else {
      this.step++;
    }
  }

  //update the characters previous position
  updatePrevPos(newX, newY) {
    this.previousPosition.x = newX;
    this.previousPosition.y = newY;
  }

  setDirection(dir) {
    this.dir = dir;
  }

  toggleUsed() {
    this.used = !this.used;
  }

  toggleWaiting() {
    this.waiting = !this.waiting;
  }
}
