CREATE TABLE IF NOT EXISTS Comments (
    id BIGINT NOT NULL AUTO_INCREMENT,
    comment VARCHAR(255) NOT NULL,
    created_date DATE NOT NULL DEFAULT CURRENT_DATE,
    car_id BIGINT,
    PRIMARY KEY (id),
    FOREIGN KEY (car_id) REFERENCES cars(id)
);