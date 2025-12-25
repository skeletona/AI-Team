mod db;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tasks = db::list_tasks()?;
    println!("{:#?}", tasks);

    Ok(())
}
