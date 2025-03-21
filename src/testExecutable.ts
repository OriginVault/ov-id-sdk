export const execute = function() {
    if (!document.getElementById('playful-canvas')) {
        const canvas = document.createElement('canvas');
        canvas.id = 'playful-canvas';
        canvas.style.position = 'fixed';
        canvas.style.top = '0';
        canvas.style.left = '0';
        canvas.style.width = '100vw';
        canvas.style.height = '100vh';
        canvas.style.zIndex = '9999';
        document.body.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        class Ball {
            x: number;
            y: number;
            radius: number;
            dx: number;
            dy: number;
            color: string;

            constructor() {
                this.x = Math.random() * canvas.width;
                this.y = Math.random() * canvas.height;
                this.radius = 20 + Math.random() * 20;
                this.dx = (Math.random() - 0.5) * 10;
                this.dy = (Math.random() - 0.5) * 10;
                this.color = `hsl(${Math.random() * 360}, 100%, 50%)`;
            }

            draw() {
                ctx?.beginPath();
                ctx?.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
                if(ctx?.fillStyle) {
                    ctx.fillStyle = this.color;
                }
                ctx?.fill();
            }

            update() {
                this.x += this.dx;
                this.y += this.dy;

                if (this.x - this.radius < 0 || this.x + this.radius > canvas.width) {
                    this.dx = -this.dx;
                }
                if (this.y - this.radius < 0 || this.y + this.radius > canvas.height) {
                    this.dy = -this.dy;
                }

                this.draw();
            }
        }

        let balls: Ball[] = [];

        function init() {
            balls = [];
            for (let i = 0; i < 10; i++) {
                balls.push(new Ball());
            }
        }

        function animate() {
            ctx?.clearRect(0, 0, canvas.width, canvas.height);
            balls.forEach(ball => ball.update());
            requestAnimationFrame(animate);
        }

        init();
        animate();

        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            init();
        });

        // Click to add new bouncing balls
        canvas.addEventListener('click', () => {
            balls.push(new Ball());
        });

        // Escape key to remove the effect
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                canvas.remove();
            }
        });
    }
}
